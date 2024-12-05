// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of bpfman

use std::collections::HashMap;

use anyhow::bail;
use bpfman::{
    add_programs,
    types::{
        FentryProgram, FexitProgram, KprobeProgram, Location, Program, ProgramData, TcProgram,
        TcxProgram, TracepointProgram, UprobeProgram, XdpProgram,
    },
};

use crate::{
    args::{GlobalArg, LoadFileArgs, LoadImageArgs, LoadSubcommand},
    table::ProgTable,
};

impl LoadSubcommand {
    pub(crate) async fn execute(&self) -> anyhow::Result<()> {
        match self {
            LoadSubcommand::File(l) => execute_load_file(l).await,
            LoadSubcommand::Image(l) => execute_load_image(l).await,
        }
    }
}

pub(crate) async fn execute_load_file(args: &LoadFileArgs) -> anyhow::Result<()> {
    let bytecode_source = Location::File(args.path.clone());

    let mut progs = vec![];
    let prog_list = args.programs.clone();
    for (prog_type, name) in prog_list {
        let data = ProgramData::new(
            bytecode_source.clone(),
            name.clone(),
            args.metadata
                .clone()
                .unwrap_or_default()
                .iter()
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .collect(),
            parse_global(&args.global),
            args.map_owner_id,
        )?;
        // Need to determin the program type here (XDP, TC, etc)
        // This would not be required if we had a generic "load" function in

        let prog = match prog_type.as_str() {
            "xdp" => Program::Xdp(XdpProgram::new(data)?),
            "tc" => Program::Tc(TcProgram::new(data)?),
            "tcx" => Program::Tcx(TcxProgram::new(data)?),
            "tracepoint" => Program::Tracepoint(TracepointProgram::new(data)?),
            "kprobe" => Program::Kprobe(KprobeProgram::new(data)?),
            "uprobe" => Program::Uprobe(UprobeProgram::new(data)?),
            "fentry" => Program::Fentry(FentryProgram::new(data, name)?),
            "fexit" => Program::Fexit(FexitProgram::new(data, name)?),
            _ => bail!("Unknown program type: {prog_type}"),
        };
        progs.push(prog);
    }

    let programs = add_programs(progs).await?;
    for program in programs {
        ProgTable::new_program(&program)?.print();
        ProgTable::new_kernel_info(&program)?.print();
    }
    Ok(())
}

pub(crate) async fn execute_load_image(args: &LoadImageArgs) -> anyhow::Result<()> {
    let bytecode_source = Location::Image((&args.pull_args).try_into()?);
    let mut progs = vec![];
    let prog_list = args.programs.clone();

    for (prog_type, name) in prog_list {
        let data = ProgramData::new(
            bytecode_source.clone(),
            name.clone(),
            args.metadata
                .clone()
                .unwrap_or_default()
                .iter()
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .collect(),
            parse_global(&args.global),
            args.map_owner_id,
        )?;

        // Need to determine the program type here (XDP, TC, etc)
        // This would not be required if we had a generic "load" function in

        let prog = match prog_type.as_str() {
            "xdp" => Program::Xdp(XdpProgram::new(data)?),
            "tc" => Program::Tc(TcProgram::new(data)?),
            "tcx" => Program::Tcx(TcxProgram::new(data)?),
            "tracepoint" => Program::Tracepoint(TracepointProgram::new(data)?),
            "kprobe" => Program::Kprobe(KprobeProgram::new(data)?),
            "uprobe" => Program::Uprobe(UprobeProgram::new(data)?),
            "fentry" => Program::Fentry(FentryProgram::new(data, name)?),
            "fexit" => Program::Fexit(FexitProgram::new(data, name)?),
            _ => bail!("Unknown program type: {prog_type}"),
        };
        progs.push(prog);
    }

    let programs = add_programs(progs).await?;
    for program in programs {
        ProgTable::new_program(&program)?.print();
        ProgTable::new_kernel_info(&program)?.print();
    }

    Ok(())
}

fn parse_global(global: &Option<Vec<GlobalArg>>) -> HashMap<String, Vec<u8>> {
    let mut global_data: HashMap<String, Vec<u8>> = HashMap::new();

    if let Some(global) = global {
        for g in global.iter() {
            global_data.insert(g.name.to_string(), g.value.clone());
        }
    }
    global_data
}
