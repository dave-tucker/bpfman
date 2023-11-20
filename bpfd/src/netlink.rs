// SPDX-License-Identifier: (Apache-2.0 OR MIT)
// Copyright Authors of Emerita

use std::{cell::RefCell, num::NonZeroI32};

use anyhow::anyhow;
use netlink_packet_core::{NetlinkMessage, NetlinkPayload, NLM_F_DUMP, NLM_F_REQUEST};
use netlink_packet_route::{RtnlMessage, TcMessage};
use netlink_sys::{constants::NETLINK_ROUTE, Socket, SocketAddr};

#[derive(Default, Debug, Clone)]
pub struct Interface {
    pub ifindex: u32,
    pub name: String,
    pub mac: Option<String>,
}

pub struct NetlinkManager {
    sock: RefCell<Socket>,
}

impl NetlinkManager {
    pub(crate) fn new() -> Self {
        NetlinkManager {
            sock: RefCell::new(init_sock()),
        }
    }

    fn send_message(
        &self,
        mut msg: NetlinkMessage<RtnlMessage>,
    ) -> Result<Vec<TcMessage>, anyhow::Error> {
        msg.finalize();
        let mut buf = vec![0; msg.header.length as usize];
        msg.serialize(&mut buf[..]);

        let socket = self.sock.borrow_mut();
        socket
            .send(&buf, 0)
            .expect("failed to send netlink message");

        let mut receive_buffer = vec![0; 4096];
        let mut qdiscs = Vec::new();
        loop {
            let n = socket.recv(&mut &mut receive_buffer[..], 0)?;
            let bytes = &receive_buffer[..n];
            let rx_packet = <NetlinkMessage<RtnlMessage>>::deserialize(bytes).unwrap();
            match rx_packet.payload {
                NetlinkPayload::InnerMessage(message) => {
                    if let RtnlMessage::NewQueueDiscipline(tc_message) = message {
                        qdiscs.push(tc_message);
                    }
                    continue;
                }
                NetlinkPayload::Done(_) => {
                    return Ok(qdiscs);
                }
                NetlinkPayload::Error(e) => {
                    if e.code == NonZeroI32::new(-17) {
                        return Ok(vec![]);
                    } else {
                        return Err(anyhow!(e));
                    }
                }
                m => return Err(anyhow!("unexpected netlink message {:?}", m)),
            }
        }
    }

    pub(crate) fn get_qdisc(&self, if_index: i32) -> Result<Vec<TcMessage>, anyhow::Error> {
        let mut socket = Socket::new(NETLINK_ROUTE).unwrap();
        socket.bind_auto().unwrap();
        socket.connect(&SocketAddr::new(0, 0)).unwrap();

        let msg = TcMessage::with_index(if_index);
        let mut req = NetlinkMessage::from(RtnlMessage::GetQueueDiscipline(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_DUMP;

        self.send_message(req)
    }
}

fn init_sock() -> Socket {
    let mut socket = Socket::new(NETLINK_ROUTE).unwrap();
    socket.bind_auto().unwrap();
    socket.connect(&SocketAddr::new(0, 0)).unwrap();
    socket
}
