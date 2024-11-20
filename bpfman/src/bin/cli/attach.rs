// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of bpfman

use anyhow::bail;
use bpfman::{
    attach_program,
    types::{AttachInfo, TcProceedOn, XdpProceedOn},
};

use crate::args::{AttachArgs, AttachCommands};

pub(crate) async fn execute_attach(args: &AttachArgs) -> anyhow::Result<()> {
    attach_program(args.program_id, args.command.get_attach_info()?).await?;
    Ok(())
}

impl AttachCommands {
    pub(crate) fn get_attach_info(&self) -> Result<Option<AttachInfo>, anyhow::Error> {
        match self {
            AttachCommands::Xdp {
                iface,
                priority,
                proceed_on,
            } => {
                let proc_on = match XdpProceedOn::from_strings(proceed_on) {
                    Ok(p) => p,
                    Err(e) => bail!("error parsing proceed_on {e}"),
                };
                Ok(Some(AttachInfo::Xdp {
                    priority: *priority,
                    iface: iface.to_string(),
                    proceed_on: proc_on,
                }))
            }
            AttachCommands::Tc {
                direction,
                iface,
                priority,
                proceed_on,
            } => {
                match direction.as_str() {
                    "ingress" | "egress" => (),
                    other => bail!("{} is not a valid direction", other),
                };
                let proc_on = match TcProceedOn::from_strings(proceed_on) {
                    Ok(p) => p,
                    Err(e) => bail!("error parsing proceed_on {e}"),
                };
                Ok(Some(AttachInfo::Tc {
                    priority: *priority,
                    iface: iface.to_string(),
                    direction: direction.to_string(),
                    proceed_on: proc_on,
                }))
            }
            AttachCommands::Tcx {
                direction,
                iface,
                priority,
            } => {
                match direction.as_str() {
                    "ingress" | "egress" => (),
                    other => bail!("{} is not a valid direction", other),
                };
                Ok(Some(AttachInfo::Tcx {
                    priority: *priority,
                    iface: iface.to_string(),
                    direction: direction.to_string(),
                }))
            }
            AttachCommands::Tracepoint { tracepoint } => Ok(Some(AttachInfo::Tracepoint {
                tracepoint: tracepoint.to_string(),
            })),
            AttachCommands::Kprobe {
                fn_name,
                offset,
                retprobe,
                container_pid,
            } => {
                if container_pid.is_some() {
                    bail!("kprobe container option not supported yet");
                }
                let offset = offset.unwrap_or(0);
                Ok(Some(AttachInfo::Kprobe {
                    fn_name: fn_name.to_string(),
                    offset,
                    retprobe: *retprobe,
                    container_pid: None,
                }))
            }
            AttachCommands::Uprobe {
                fn_name,
                offset,
                target,
                retprobe,
                pid,
                container_pid,
            } => {
                let offset = offset.unwrap_or(0);
                Ok(Some(AttachInfo::Uprobe {
                    fn_name: fn_name.clone(),
                    offset,
                    target: target.to_string(),
                    retprobe: *retprobe,
                    pid: *pid,
                    container_pid: *container_pid,
                }))
            }
            AttachCommands::Fentry { .. } | AttachCommands::Fexit { .. } => Ok(None),
        }
    }
}
