// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of bpfman
use bpfman::{
    add_programs, attach_program, get_program, list_programs, pull_bytecode, remove_program,
    types::{
        AttachInfo, FentryProgram, FexitProgram, KprobeProgram, ListFilter, Location, Program,
        ProgramData, TcProceedOn, TcProgram, TcxProgram, TracepointProgram, UprobeProgram,
        XdpProceedOn, XdpProgram,
    },
};
use bpfman_api::v1::{
    attach_info::Info, bpfman_server::Bpfman, bytecode_location::Location as RpcLocation,
    list_response::ListResult, AttachRequest, AttachResponse, BpfmanProgramType, GetRequest,
    GetResponse, ListRequest, ListResponse, LoadRequest, LoadResponse, LoadResponseInfo,
    ProgSpecificInfo, PullBytecodeRequest, PullBytecodeResponse, UnloadRequest, UnloadResponse,
};
use tonic::{Request, Response, Status};

pub struct BpfmanLoader {}

impl BpfmanLoader {
    pub(crate) fn new() -> BpfmanLoader {
        BpfmanLoader {}
    }
}

#[tonic::async_trait]
impl Bpfman for BpfmanLoader {
    async fn load(&self, request: Request<LoadRequest>) -> Result<Response<LoadResponse>, Status> {
        let request = request.into_inner();

        let bytecode_source = match request
            .bytecode
            .ok_or(Status::aborted("missing bytecode info"))?
            .location
            .ok_or(Status::aborted("missing location"))?
        {
            RpcLocation::Image(i) => Location::Image(i.into()),
            RpcLocation::File(p) => Location::File(p),
        };

        let programs : Vec<Result<Program, Status>> = request.info.iter().map(|info| {
            let data = ProgramData::new(
                bytecode_source.clone(),
                info.name.clone(),
                request.metadata.clone(),
                request.global_data.clone(),
                request.map_owner_id,
            )
            .map_err(|e| Status::aborted(format!("failed to create ProgramData: {e}")))?;

            let program = match info.program_type() {
                BpfmanProgramType::Xdp => Program::Xdp(XdpProgram::new(data).map_err(|e| {
                    Status::aborted(format!("failed to create XdpProgram: {e}"))})?),
                BpfmanProgramType::Tc => Program::Tc(TcProgram::new(data).map_err(|e| {
                    Status::aborted(format!("failed to create TcProgram: {e}"))})?),
                BpfmanProgramType::Tcx => Program::Tcx(TcxProgram::new(data).map_err(|e| {
                    Status::aborted(format!("failed to create TcxProgram: {e}"))})?),
                BpfmanProgramType::Tracepoint => Program::Tracepoint(TracepointProgram::new(data).map_err(|e| {
                    Status::aborted(format!("failed to create TracepoinProgram: {e}"))})?),
                BpfmanProgramType::Kprobe => Program::Kprobe(KprobeProgram::new(data).map_err(|e| {
                    Status::aborted(format!("failed to create KprobeProgram: {e}"))})?),
                BpfmanProgramType::Uprobe => Program::Uprobe(UprobeProgram::new(data).map_err(|e| {
                    Status::aborted(format!("failed to create UprobeProgram: {e}"))})?),
                BpfmanProgramType::Fentry => {
                    if let Some(ProgSpecificInfo {
                        info: Some(bpfman_api::v1::prog_specific_info::Info::FentryLoadInfo(fentry)),
                    }) = &info.info
                    {
                        Program::Fentry(FentryProgram::new(data, fentry.fn_name.clone()).map_err(|e| {
                            Status::aborted(format!("failed to create FentryProgram: {e}"))})?)
                    } else {
                        return Err(Status::aborted("missing FentryInfo"));
                    }
                }
                BpfmanProgramType::Fexit => {
                    if let Some(ProgSpecificInfo {
                        info: Some(bpfman_api::v1::prog_specific_info::Info::FexitLoadInfo(fexit)),
                    }) = &info.info
                    {
                        Program::Fexit(FexitProgram::new(data, fexit.fn_name.clone()).map_err(|e| {
                            Status::aborted(format!("failed to create FexitProgram: {e}"))})?)
                    } else {
                        return Err(Status::aborted("missing FexitInfo"));
                    }
                }
            };
            Ok(program)
        }).collect();

        // Check if any of the programs failed to be created
        for p in programs.iter() {
            if let Err(e) = p {
                return Err(e.clone());
            }
        }

        let add_prog_result = add_programs(programs.into_iter().map(|p| p.unwrap()).collect())
            .await
            .map_err(|e| Status::aborted(format!("{e}")))?;

        let response = add_prog_result
            .iter()
            .map(|p| LoadResponseInfo {
                info: Some(
                    p.try_into()
                        .map_err(|e| {
                            Status::aborted(format!("convert Program to GRPC program: {e}"))
                        })
                        .unwrap(),
                ),
                kernel_info: Some(
                    (p).try_into()
                        .map_err(|e| {
                            Status::aborted(format!(
                                "convert Program to GRPC kernel program info: {e}"
                            ))
                        })
                        .unwrap(),
                ),
            })
            .collect();

        let reply_entry = LoadResponse { programs: response };

        Ok(Response::new(reply_entry))
    }

    async fn unload(
        &self,
        request: Request<UnloadRequest>,
    ) -> Result<Response<UnloadResponse>, Status> {
        let reply = UnloadResponse {};
        let request = request.into_inner();

        remove_program(request.id)
            .await
            .map_err(|e| Status::aborted(format!("{e}")))?;

        Ok(Response::new(reply))
    }

    async fn attach(
        &self,
        request: Request<AttachRequest>,
    ) -> Result<Response<AttachResponse>, Status> {
        let reply = AttachResponse {};
        let request = request.into_inner();

        let attach_info = if let Some(info) = request.attach {
            let attach_info = info.info.ok_or(Status::aborted("missing attach info"))?;
            match attach_info {
                Info::XdpAttachInfo(i) => Some(AttachInfo::Xdp {
                    priority: i.priority,
                    iface: i.iface,
                    proceed_on: XdpProceedOn::from_int32s(i.proceed_on)
                        .map_err(|_| Status::aborted("failed to parse proceed_on"))?,
                }),
                Info::TcAttachInfo(i) => Some(AttachInfo::Tc {
                    priority: i.priority,
                    iface: i.iface,
                    direction: i.direction,
                    proceed_on: TcProceedOn::from_int32s(i.proceed_on)
                        .map_err(|_| Status::aborted("failed to parse proceed_on"))?,
                }),
                Info::TcxAttachInfo(i) => Some(AttachInfo::Tcx {
                    priority: i.priority,
                    iface: i.iface,
                    direction: i.direction,
                }),
                Info::TracepointAttachInfo(i) => Some(AttachInfo::Tracepoint {
                    tracepoint: i.tracepoint,
                }),
                Info::KprobeAttachInfo(i) => Some(AttachInfo::Kprobe {
                    fn_name: i.fn_name,
                    offset: i.offset,
                    retprobe: i.retprobe,
                    container_pid: i.container_pid,
                }),
                Info::UprobeAttachInfo(i) => Some(AttachInfo::Uprobe {
                    fn_name: i.fn_name,
                    offset: i.offset,
                    target: i.target,
                    retprobe: i.retprobe,
                    pid: i.pid,
                    container_pid: i.container_pid,
                }),
            }
        } else {
            None
        };

        attach_program(request.id, attach_info)
            .await
            .map_err(|e| Status::aborted(format!("{e}")))?;

        Ok(Response::new(reply))
    }

    async fn get(&self, request: Request<GetRequest>) -> Result<Response<GetResponse>, Status> {
        let request = request.into_inner();
        let id = request.id;

        let program = get_program(id)
            .await
            .map_err(|e| Status::aborted(format!("{e}")))?;

        let reply_entry =
            GetResponse {
                info: if let Program::Unsupported(_) = program {
                    None
                } else {
                    Some((&program).try_into().map_err(|e| {
                        Status::aborted(format!("failed to get program metadata: {e}"))
                    })?)
                },
                kernel_info: Some((&program).try_into().map_err(|e| {
                    Status::aborted(format!("convert Program to GRPC kernel program info: {e}"))
                })?),
            };
        Ok(Response::new(reply_entry))
    }

    async fn list(&self, request: Request<ListRequest>) -> Result<Response<ListResponse>, Status> {
        let mut reply = ListResponse { results: vec![] };

        let filter = ListFilter::new(
            request.get_ref().program_type,
            request.get_ref().match_metadata.clone(),
            request.get_ref().bpfman_programs_only(),
        );

        // Await the response
        for r in list_programs(filter)
            .await
            .map_err(|e| Status::aborted(format!("failed to list programs: {e}")))?
        {
            // Populate the response with the Program Info and the Kernel Info.
            let reply_entry = ListResult {
                info: if let Program::Unsupported(_) = r {
                    None
                } else {
                    Some((&r).try_into().map_err(|e| {
                        Status::aborted(format!("failed to get program metadata: {e}"))
                    })?)
                },
                kernel_info: Some((&r).try_into().map_err(|e| {
                    Status::aborted(format!("convert Program to GRPC kernel program info: {e}"))
                })?),
            };
            reply.results.push(reply_entry)
        }
        Ok(Response::new(reply))
    }

    async fn pull_bytecode(
        &self,
        request: tonic::Request<PullBytecodeRequest>,
    ) -> std::result::Result<tonic::Response<PullBytecodeResponse>, tonic::Status> {
        let request = request.into_inner();
        let image = match request.image {
            Some(i) => i.into(),
            None => return Err(Status::aborted("Empty pull_bytecode request received")),
        };

        pull_bytecode(image)
            .await
            .map_err(|e| Status::aborted(format!("{e}")))?;

        let reply = PullBytecodeResponse {};
        Ok(Response::new(reply))
    }
}
