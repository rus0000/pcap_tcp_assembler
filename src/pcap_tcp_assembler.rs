/*
 * @copyright (C) 2024 Ruslan Iusupov <https://github.com/rus0000>
 *
 * SPDX-License-Identifier: MIT
 */
use std::net::Ipv4Addr;
use std::{collections::HashMap, fmt};

use etherparse::{Ipv4HeaderSlice, TcpHeaderSlice};
use indexmap::IndexMap;

use crate::assembler::Assembler;

pub fn check_trace_connection(trace_connections: &[u32], connection_id: u32) -> bool {
    trace_connections.contains(&connection_id) || trace_connections.len() == 0
}

macro_rules! trace {
    ($format_pattern: expr, $trace_connections: expr, $connection_id: expr, $($arg: expr),*) => {
        if check_trace_connection($trace_connections, $connection_id) {
            println!($format_pattern, $connection_id, $($arg),*);
        };
    }
}

/// TCP connection tuple, two IPs + two ports.
/// TCP session consist of two TCP connections.
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone)]
pub struct TcpConnection {
    // IP Addresses are unique identification of inner VLAN
    pub source_ipv4_address: Ipv4Addr,
    pub source_port: u16,

    pub destination_ipv4_address: Ipv4Addr,
    pub destination_port: u16,
}
impl Default for TcpConnection {
    fn default() -> Self {
        Self {
            source_ipv4_address: Ipv4Addr::new(0, 0, 0, 0),
            source_port: 0,
            destination_ipv4_address: Ipv4Addr::new(0, 0, 0, 0),
            destination_port: 0,
        }
    }
}

impl fmt::Debug for TcpConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "(ip.addr == {} && ip.addr == {} && tcp.port == {} && tcp.port == {})",
            self.source_ipv4_address, self.destination_ipv4_address, self.source_port, self.destination_port,
        )
    }
}
impl TcpConnection {
    pub fn get_reverse_connection(&self) -> Self {
        TcpConnection {
            source_ipv4_address: self.destination_ipv4_address,
            source_port: self.destination_port,

            destination_ipv4_address: self.source_ipv4_address,
            destination_port: self.source_port,
        }
    }
}

/// Allocated 2x times per each TCP connection. One in each direction: source -> destination.
#[derive(Debug)]
pub struct TcpReceiveStorage {
    pub tcp_connection: TcpConnection,
    pub connection_id: u32,
    /// Avoid processing of same TCP packet, captured twice.
    pub stick_to_outer_vlan: u16,
    pub tcp_assembler: Assembler,
    /// Pre-allocated receive buffers, A and B.
    pub receive_buffers: (Vec<u8>, Vec<u8>),
    /// 0 == A, 1 == B in receive_buffers
    pub current_receive_buffer: u8,
    /// Raw sequence number from SYN
    pub trace_start_sequence_number: u32,
    /// Raw sequence number of first byte in active receive_buffer
    pub last_consumed_sequence_number: u32,
    // Size of buffered data is stored by tcp_assembler
}

impl TcpReceiveStorage {
    pub fn new(
        receive_buffer_size: usize,
        tcp_assembler_size: usize,
        tcp_connection: TcpConnection,
        connection_id: u32,
        outer_vlan_id: u16,
        start_sequence_number: u32,
        is_syn: bool,
    ) -> Self {
        Self {
            tcp_connection,
            connection_id,
            stick_to_outer_vlan: outer_vlan_id,
            tcp_assembler: Assembler::new(tcp_assembler_size),
            receive_buffers: (vec![0; receive_buffer_size], vec![0; receive_buffer_size]),
            current_receive_buffer: 0,
            trace_start_sequence_number: start_sequence_number,
            last_consumed_sequence_number: start_sequence_number + if is_syn { 1 } else { 0 },
            // last_buffered_sequence_number: 0,
            // sequence_number_to_segment_size: IndexMap::<u32, u32>::new(),
        }
    }
}

/// * Please see [Implementation.md](https://github.com/rus0000/pcap_tcp_assembler/blob/master/Implementation.md) on GitHub.
/// * Create single instance of [PcapTcpAssembler] per application.
/// * In [PcapTcpAssembler::new()] provide receive buffer size, amount of tracking holes in TCP byte-stream and tracing option.
/// * Iterate PCAP packets. For each TCP packet call [PcapTcpAssembler::handle_segment()]
///     * Provide two callbacks
///     * `try_consume_tcp_payload()` to detect application message beginning and consume data
///     * `inform_packet_loss()` to handle data loss
/// * Call [PcapTcpAssembler::consume_all_buffers()] to drain all buffers at the end of PCAP file, after last segment was assembled.
#[derive(Debug)]
pub struct PcapTcpAssembler<'a> {
    //. constructor argument
    /// #header
    pub receive_buffer_size: usize,
    /// constructor argument
    pub tcp_assembler_size: usize,
    /// empty slice: trace all connections, positive values: specific connection Ids, u32::MAX: disable tracing.
    pub trace_connections: &'a [u32],
    /// IndexMap allow to stable iteration order at the and of PCAP
    pub connections: IndexMap<TcpConnection, TcpReceiveStorage>,
    /// Sticky connection id to outer VLAN
    pub connection_to_id: HashMap<TcpConnection, u32>,
    /// last generated connection Id
    pub last_connection_id: u32,
}

impl Default for PcapTcpAssembler<'_> {
    fn default() -> Self {
        PcapTcpAssembler::new(0x20000 /* 131072 == 120 K */, 100, Some(&[u32::MAX]))
    }
}

/// consume_buffer
/// # Arguments
/// * `force_to_consume` - Try to consume iteratively from each byte in buffer up to the end of continuous range.
///     Drop leading hole. When consumed, drop not consumed bytes on left. Copy remaining bytes on right to buffer B.
pub fn consume_buffer(
    trace_connections: &[u32],
    tcp_storage: &mut TcpReceiveStorage,
    try_consume_tcp_payload: &mut dyn FnMut(&[u8], u32, &TcpConnection, Option<&str>) -> u32,
    inform_packet_loss: &mut dyn FnMut(u32, &TcpConnection, u32, Option<&str>),
    force_to_consume: bool,
    trace_relative_sequence_number: u32,
) -> u32 {
    if force_to_consume {
        trace!(
            "[{}]: {} consume_buffer() force_to_consume ",
            trace_connections,
            tcp_storage.connection_id,
            trace_relative_sequence_number
        );
    }

    if tcp_storage.tcp_assembler.len() == 0 {
        return 0;
    }
    let mut consume = |tcp_storage: &mut TcpReceiveStorage, from: usize, up_to: usize| -> u32 {
        let receive_buffer = if tcp_storage.current_receive_buffer == 0 {
            &tcp_storage.receive_buffers.0
        } else {
            &tcp_storage.receive_buffers.1
        };

        let trace_str = format!("[{}]: {}", tcp_storage.connection_id, trace_relative_sequence_number);
        let consumed_size = try_consume_tcp_payload(
            &receive_buffer[from..up_to],
            tcp_storage.connection_id,
            &tcp_storage.tcp_connection,
            if check_trace_connection(trace_connections, tcp_storage.connection_id) {
                Some(&trace_str)
            } else {
                None
            },
        );
        // trace!("[{}]: trying: {}-{} consumed {}", tcp_storage.connection_id, from, up_to, consumed_size);

        consumed_size
    };

    let (leading_hole_size, contig_data_size) = tcp_storage.tcp_assembler.get_contig_data(0);
    if force_to_consume {
        /*
         * # Cases
         * ## Buffer full:
         * - Case, when leading hole is present and receive_buffer is full
         * ## Drain:
         * - Case, when stream is closed
         *
         * # Actions
         * - Drop leading hole.
         * - Iterate over bytes and try to consume
         * - Drop left unconsumed bytes and report
         * - Copy right unconsumed bytes to buffer B
         */

        // Segment with data_end is not yet received
        let data_end = leading_hole_size + contig_data_size;
        for data_iter in leading_hole_size..data_end {
            let consumed_size = consume(tcp_storage, data_iter as usize, data_end as usize);
            if consumed_size > 0 {
                let remove_from_buffer = data_iter as u32 + consumed_size;
                if tcp_storage.tcp_assembler.remove_data_at_head(remove_from_buffer as usize).is_err() {
                    trace!(
                        "[{}]: remove_data_at_head panic: {} {}",
                        trace_connections,
                        tcp_storage.connection_id,
                        leading_hole_size,
                        consumed_size
                    );
                    panic!();
                }

                trace!(
                    "[{}]: {} consumed {} bytes, dropped {} bytes",
                    trace_connections,
                    tcp_storage.connection_id,
                    trace_relative_sequence_number,
                    consumed_size,
                    data_iter
                );

                let trace_str = format!("[{}]: {}", tcp_storage.connection_id, trace_relative_sequence_number);
                if data_iter > 0 {
                    inform_packet_loss(
                        tcp_storage.connection_id,
                        &tcp_storage.tcp_connection,
                        data_iter as u32,
                        if check_trace_connection(trace_connections, tcp_storage.connection_id) {
                            Some(&trace_str)
                        } else {
                            None
                        },
                    );
                }

                let bytes_on_right = tcp_storage.tcp_assembler.len();
                if bytes_on_right == 0 {
                    return remove_from_buffer;
                }
                trace!(
                    "[{}]: {} copy_buffer force_to_consume {} {} ",
                    trace_connections,
                    tcp_storage.connection_id,
                    trace_relative_sequence_number,
                    data_iter + consumed_size as usize,
                    bytes_on_right
                );
                tcp_storage.current_receive_buffer = copy_buffer(tcp_storage, data_iter + consumed_size as usize, bytes_on_right);
                trace!(
                    "[{}]: {} receive buffer still has: {} bytes",
                    trace_connections,
                    tcp_storage.connection_id,
                    trace_relative_sequence_number,
                    bytes_on_right
                );

                return remove_from_buffer;
            }
        }
        // Whole first continuous range is garbage.
        if tcp_storage.tcp_assembler.remove_data_at_head(data_end).is_err() {
            trace!(
                "[{}]: remove_data_at_head panic: {}",
                trace_connections,
                tcp_storage.connection_id,
                data_end
            );
            panic!();
        }

        let trace_str = format!("[{}]: {}", tcp_storage.connection_id, trace_relative_sequence_number);
        inform_packet_loss(
            tcp_storage.connection_id,
            &tcp_storage.tcp_connection,
            data_end as u32,
            if check_trace_connection(trace_connections, tcp_storage.connection_id) {
                Some(&trace_str)
            } else {
                None
            },
        );

        return data_end as u32;
    } else {
        /*
         * # Mainstream case
         *  - No leading hole case.
         *  - Receive and consume only from Head of receive_buffer A.
         *  - Can consume not all of buffered data.
         *  - Copy unconsumed bytes on right to the buffer B.
         */
        assert_eq!(leading_hole_size, 0);
        let consumed_size = consume(tcp_storage, 0, contig_data_size);
        if consumed_size > 0 {
            if tcp_storage.tcp_assembler.remove_data_at_head(consumed_size as usize).is_err() {
                trace!(
                    "[{}]: remove_data_at_head panic: {}",
                    trace_connections,
                    tcp_storage.connection_id,
                    consumed_size
                );
                panic!();
            }

            trace!(
                "[{}]: {} consumed {} bytes",
                trace_connections,
                tcp_storage.connection_id,
                trace_relative_sequence_number,
                consumed_size
            );
            let bytes_on_right = tcp_storage.tcp_assembler.len();
            if bytes_on_right == 0 {
                return consumed_size;
            }
            trace!(
                "[{}]: {} copy_buffer partial consume, consumed {} bytes_on_right {}",
                trace_connections,
                tcp_storage.connection_id,
                trace_relative_sequence_number,
                consumed_size as usize,
                bytes_on_right
            );
            tcp_storage.current_receive_buffer = copy_buffer(tcp_storage, consumed_size as usize, bytes_on_right);
        }

        return consumed_size;
    }
}

pub fn copy_buffer(tcp_storage: &mut TcpReceiveStorage, offset: usize, size: usize) -> u8 {
    if tcp_storage.current_receive_buffer == 0 {
        tcp_storage.receive_buffers.1[..size].copy_from_slice(&tcp_storage.receive_buffers.0[offset..offset + size]);
        1
    } else {
        tcp_storage.receive_buffers.0[..size].copy_from_slice(&tcp_storage.receive_buffers.1[offset..offset + size]);
        0
    }
}

impl<'a> PcapTcpAssembler<'a> {
    /// # Arguments
    /// * `receive_buffer_size`: size of receive_buffer in bytes. Two buffers are allocated per TCP connection, therefore four per TCP session.
    /// * `tcp_assembler_size`: amount of holes in TCP steam to keep track of.
    /// * `trace_connections`: empty slice: trace all connections, list of values: specific connection Ids, None: disable TCP tracing.
    pub fn new(receive_buffer_size: usize, tcp_assembler_size: usize, trace_connections: Option<&'a [u32]>) -> Self {
        Self {
            receive_buffer_size,
            tcp_assembler_size,
            trace_connections: if trace_connections.is_some() {
                trace_connections.unwrap()
            } else {
                &[u32::MAX]
            },
            connections: IndexMap::<TcpConnection, TcpReceiveStorage>::new(),
            connection_to_id: HashMap::<TcpConnection, u32>::new(),
            last_connection_id: 0,
        }
    }

    /// Get id of TCP connection, insert an new one, if missing. Creates also reverse connection id, if needed.
    pub fn get_connection_id(&mut self, tcp_connection: &TcpConnection) -> u32 {
        let connection_id = *self.connection_to_id.entry(tcp_connection.clone()).or_insert_with(|| {
            self.last_connection_id += 1;
            self.last_connection_id
        });

        // Generate also reverse connection id to make it consecutive number.
        self.connection_to_id.entry(tcp_connection.get_reverse_connection()).or_insert_with(|| {
            self.last_connection_id += 1;
            self.last_connection_id
        });

        connection_id
    }
    /// * Drain all buffers.
    /// * Must be called at the end of PCAP file, after last segment was assembled.
    /// # Arguments
    /// * Same callbacks as for [PcapTcpAssembler::handle_segment].
    pub fn consume_all_buffers(
        &mut self,
        try_consume_tcp_payload: &mut dyn FnMut(&[u8], u32, &TcpConnection, Option<&str>) -> u32,
        inform_packet_loss: &mut dyn FnMut(u32, &TcpConnection, u32, Option<&str>),
    ) {
        for (_tcp_connection, tcp_storage) in self.connections.iter_mut() {
            while tcp_storage.tcp_assembler.len() > 0 {
                tcp_storage.last_consumed_sequence_number += consume_buffer(
                    self.trace_connections,
                    tcp_storage,
                    try_consume_tcp_payload,
                    inform_packet_loss,
                    true,
                    tcp_storage.last_consumed_sequence_number,
                );
            }
        }
    }

    /// Main function for assembling TCP segments
    /// # Arguments
    /// * `outer_vlan_identifier`: Allow to filter out duplicated packets if they are captured twice. Typical by complex tracing setups with hardware Probes.
    /// * `ipv4_header_slice`: etherparse type
    /// * `tcp_header_slice`: etherparse type
    /// * `tcp_payload`: Payload of TCP segment to assemble it into TCP byte-stream
    /// * `try_consume_tcp_payload`: Callback to detect application message and consume it
    ///     * `consumable_tcp_payload`:
    ///         * At first step, application should try to detect a message beginning starting only from beginning of this slice.
    ///         * If not detected, return 0, if detected, then application should consume as much as possible and return amount of consumed bytes.
    ///         * At next steps, when message header is already consumed, application should continue consuming chunks and return non zero value of consumed bytes.
    ///     * `connection_id`: TCP connection id, generated sequentially as it is found in a PCAP.
    ///         * Forward and reverse connection IDs of same TCP session are generated at once. So odd and next even connection Ids always form a TCP session.
    ///     * `tcp_connection`: TCP connection tuple, two IPs + two ports
    ///     * `trace`: If TCP tracing is enabled, then it will contain a tracing substring, which could be added to application message tracing
    /// * `inform_packet_loss`: Callback to inform application about data loss
    ///     * `connection_id`: see above
    ///     * `tcp_connection`: see above
    ///     * `lost_bytes`: amount of dropped bytes
    ///     * `trace`: see above
    pub fn handle_segment(
        &mut self,
        outer_vlan_identifier: Option<u16>,
        ipv4_header_slice: &Ipv4HeaderSlice,
        tcp_header_slice: &TcpHeaderSlice,
        tcp_payload: &[u8],
        try_consume_tcp_payload: &mut dyn FnMut(
            /* consumable_tcp_payload */ &[u8],
            /* connection_id */ u32,
            /* tcp_connection */ &TcpConnection,
            /* trace */ Option<&str>,
        ) -> u32,
        inform_packet_loss: &mut dyn FnMut(
            /* connection_id */ u32,
            /* tcp_connection */ &TcpConnection,
            /* lost_bytes */ u32,
            /* trace */ Option<&str>,
        ),
    ) {
        let outer_vlan_identifier = if outer_vlan_identifier.is_some() {
            outer_vlan_identifier.unwrap()
        } else {
            0
        };
        let tcp_connection = TcpConnection {
            source_ipv4_address: ipv4_header_slice.source().into(),
            destination_ipv4_address: ipv4_header_slice.destination().into(),
            source_port: tcp_header_slice.source_port(),
            destination_port: tcp_header_slice.destination_port(),
        };

        let mut trace_relative_sequence_number: u32 = 1;

        let tcp_storage_option = self.connections.get_mut(&tcp_connection);
        if outer_vlan_identifier != 0 {
            // Ignore outer VLAN duplicated packets.
            // Use packets from the outer VLAN, which has appeared first. It doesn't matter which one.
            // Ignore all packets from same connection on other VLANs.
            // Avoid processing of same TCP packet, captured twice.
            if tcp_storage_option.is_some() && tcp_storage_option.as_ref().unwrap().stick_to_outer_vlan != outer_vlan_identifier {
                return;
            };
        }

        if tcp_storage_option.is_some() {
            if tcp_header_slice.sequence_number() < tcp_storage_option.as_deref().unwrap().trace_start_sequence_number {
                trace!(
                    "[{}]: {} Sequence number smaller than start_sequence_number {}",
                    self.trace_connections,
                    tcp_storage_option.as_deref().unwrap().connection_id,
                    tcp_header_slice.sequence_number(),
                    tcp_storage_option.as_deref().unwrap().trace_start_sequence_number
                );
                if let Some(removed_storage) = self.connections.shift_remove(&tcp_connection) {
                    trace!(
                        "[{}]: {} Remove connection",
                        self.trace_connections,
                        removed_storage.connection_id,
                        tcp_header_slice.sequence_number()
                    );
                };

                return;
            }
            trace_relative_sequence_number = tcp_header_slice.sequence_number() - tcp_storage_option.unwrap().trace_start_sequence_number + 1;
        }

        if tcp_header_slice.rst() || tcp_header_slice.fin() {
            if let Some(mut removed_storage) = self.connections.shift_remove(&tcp_connection) {
                trace!(
                    "[{}]: {} RST or FIN, remove connection",
                    self.trace_connections,
                    removed_storage.connection_id,
                    trace_relative_sequence_number
                );
                while removed_storage.tcp_assembler.len() > 0 {
                    removed_storage.last_consumed_sequence_number += consume_buffer(
                        self.trace_connections,
                        &mut removed_storage,
                        try_consume_tcp_payload,
                        inform_packet_loss,
                        true,
                        trace_relative_sequence_number,
                    );
                }
            };

            let connection_id = self.get_connection_id(&tcp_connection);
            let reversed_connection = tcp_connection.get_reverse_connection();
            if let Some(mut removed_storage) = self.connections.shift_remove(&reversed_connection) {
                trace!(
                    "[{}]: {} RST or FIN, remove reverse connection [{}]: {}",
                    self.trace_connections,
                    connection_id,
                    trace_relative_sequence_number,
                    removed_storage.connection_id,
                    removed_storage.last_consumed_sequence_number - removed_storage.trace_start_sequence_number
                );
                while removed_storage.tcp_assembler.len() > 0 {
                    removed_storage.last_consumed_sequence_number += consume_buffer(
                        self.trace_connections,
                        &mut removed_storage,
                        try_consume_tcp_payload,
                        inform_packet_loss,
                        true,
                        trace_relative_sequence_number,
                    );
                }
            };

            return;
        } else if tcp_header_slice.syn() {
            if let Some(mut removed_storage) = self.connections.shift_remove(&tcp_connection) {
                trace!(
                    "[{}]: {} SYN, remove connection",
                    self.trace_connections,
                    removed_storage.connection_id,
                    trace_relative_sequence_number
                );
                while removed_storage.tcp_assembler.len() > 0 {
                    removed_storage.last_consumed_sequence_number += consume_buffer(
                        self.trace_connections,
                        &mut removed_storage,
                        try_consume_tcp_payload,
                        inform_packet_loss,
                        true,
                        trace_relative_sequence_number,
                    );
                }
            };

            let connection_id = self.get_connection_id(&tcp_connection);

            self.connections.insert(
                tcp_connection.clone(),
                TcpReceiveStorage::new(
                    self.receive_buffer_size,
                    self.tcp_assembler_size,
                    tcp_connection.clone(),
                    connection_id,
                    outer_vlan_identifier,
                    tcp_header_slice.sequence_number(),
                    true,
                ),
            );
            let tcp_flag = if tcp_header_slice.ack() { "SYN + ACK" } else { "SYN no ACK" };
            trace!(
                "[{}]: {} {}, new connection, outer VLAN {} {:?}",
                self.trace_connections,
                connection_id,
                trace_relative_sequence_number,
                tcp_flag,
                outer_vlan_identifier,
                tcp_connection
            );

            if !tcp_header_slice.ack() {
                let reversed_connection = tcp_connection.get_reverse_connection();
                if let Some(mut removed_storage) = self.connections.shift_remove(&reversed_connection) {
                    trace!(
                        "[{}]: {} SYN no ACK, remove reverse connection [{}]: {}",
                        self.trace_connections,
                        connection_id,
                        trace_relative_sequence_number,
                        removed_storage.connection_id,
                        removed_storage.last_consumed_sequence_number - removed_storage.trace_start_sequence_number
                    );
                    while removed_storage.tcp_assembler.len() > 0 {
                        removed_storage.last_consumed_sequence_number += consume_buffer(
                            self.trace_connections,
                            &mut removed_storage,
                            try_consume_tcp_payload,
                            inform_packet_loss,
                            true,
                            trace_relative_sequence_number,
                        );
                    }
                };
            }
        }

        // TODO: Adapt to etherparse 0.15.0
        // let Ok(ip_payload_len) = ipv4_header_slice.payload_len() else {
        //     return;
        // };
        let tcp_segment_size: u32 = ipv4_header_slice.payload_len() as u32 - tcp_header_slice.data_offset() as u32 * 4;

        if tcp_segment_size == 0 || (tcp_payload.len() as u32) < tcp_segment_size {
            return;
        }

        let connection_id = self.get_connection_id(&tcp_connection);
        let tcp_storage = self.connections.entry(tcp_connection.clone()).or_insert_with(|| {
            let new_tcp_storage = TcpReceiveStorage::new(
                self.receive_buffer_size,
                self.tcp_assembler_size,
                tcp_connection.clone(),
                connection_id,
                outer_vlan_identifier,
                tcp_header_slice.sequence_number(),
                false,
            );
            trace!(
                "[{}]: {}/{} No SYN, new connection, outer VLAN {} {:?}",
                self.trace_connections,
                connection_id,
                trace_relative_sequence_number,
                tcp_header_slice.sequence_number(),
                outer_vlan_identifier,
                tcp_connection
            );

            new_tcp_storage
        });

        if tcp_header_slice.sequence_number() < tcp_storage.last_consumed_sequence_number {
            trace!(
                "[{}]: {} tcp_storage TCP retransmission, already assembled, ignoring. sequence_number {} last_assembled_sequence_number {}",
                self.trace_connections,
                tcp_storage.connection_id,
                trace_relative_sequence_number,
                tcp_header_slice.sequence_number(),
                tcp_storage.last_consumed_sequence_number
            );

            return;
        }

        let mut payload_offset = tcp_header_slice.sequence_number() - tcp_storage.last_consumed_sequence_number;

        // Segment does not fit to the `receive_buffer`. Buffer is full. Force to consume.
        while payload_offset + tcp_segment_size > self.receive_buffer_size as u32 {
            if tcp_storage.tcp_assembler.len() == 0 {
                let trace_str = format!("[{}]: {}", tcp_storage.connection_id, trace_relative_sequence_number);
                inform_packet_loss(
                    tcp_storage.connection_id,
                    &tcp_connection,
                    payload_offset as u32,
                    if check_trace_connection(self.trace_connections, tcp_storage.connection_id) {
                        Some(&trace_str)
                    } else {
                        None
                    },
                );
                tcp_storage.last_consumed_sequence_number = tcp_header_slice.sequence_number();
                payload_offset = 0;

                break;
            }
            tcp_storage.last_consumed_sequence_number += consume_buffer(
                self.trace_connections,
                tcp_storage,
                try_consume_tcp_payload,
                inform_packet_loss,
                true,
                trace_relative_sequence_number,
            );
            payload_offset = tcp_header_slice.sequence_number() - tcp_storage.last_consumed_sequence_number;
        }

        let tcp_assembler = &mut tcp_storage.tcp_assembler;
        let receive_buffer = if tcp_storage.current_receive_buffer == 0 {
            &mut tcp_storage.receive_buffers.0
        } else {
            &mut tcp_storage.receive_buffers.1
        };

        receive_buffer[payload_offset as usize..(payload_offset + tcp_segment_size) as usize]
            .copy_from_slice(&tcp_payload[..tcp_segment_size as usize]);

        // tcp_storage.last_buffered_sequence_number = tcp_header_slice.sequence_number() + tcp_segment_size;

        let result = tcp_assembler.insert_data_absolute(payload_offset as usize, tcp_segment_size as usize);
        if result.is_ok() {
            // Detailed logging of tcp_assembler
            // trace!(
            //     "[{}]: {} tcp_segment_size {} tcp_assembler {:?}",
            //     tcp_storage.connection_id,
            //     trace_relative_sequence_number,
            //     tcp_segment_size,
            //     tcp_assembler
            // );
            trace!(
                "[{}]: {} tcp_segment_size {} ",
                self.trace_connections,
                tcp_storage.connection_id,
                trace_relative_sequence_number,
                tcp_segment_size
            );
        } else {
            trace!(
                "[{}]: {} Assembler: TooManyHoles tcp_segment_size {} tcp_assembler {:?}",
                self.trace_connections,
                tcp_storage.connection_id,
                trace_relative_sequence_number,
                tcp_segment_size,
                tcp_assembler
            );
        }

        // Leading hole. Can consume only when either hole is filled or receive_buffer is full.
        if tcp_assembler.peek_front() == 0 {
            return;
        }

        // Mainstream use-case. Try to consume as soon as segment received.
        tcp_storage.last_consumed_sequence_number += consume_buffer(
            self.trace_connections,
            tcp_storage,
            try_consume_tcp_payload,
            inform_packet_loss,
            false,
            trace_relative_sequence_number,
        );
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_pcap_tcp_assembler() {
        let _pcap_tcp_assembler = PcapTcpAssembler::new(0x2000, 10, Some(&[]));
    }
}
