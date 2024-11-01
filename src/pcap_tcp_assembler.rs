/*
 * @copyright (C) 2024 Ruslan Iusupov <https://github.com/rus0000>
 *
 * SPDX-License-Identifier: MIT
 */
use std::collections::HashMap;

use etherparse::{Ipv4HeaderSlice, TcpHeaderSlice};
use indexmap::IndexMap;

use crate::{
    consume_buffer::consume_buffer, tcp_connection::TcpConnection, tcp_receive_storage::TcpReceiveStorage, trace, trace_macro::check_trace_connection,
};

pub const MAX_SEQUENCE_NUMBER: u32 = u32::MAX;
pub const SEQUENCE_NUMBER_OLD_DUPLICATE_THRESHOLD: u32 = 65536;

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
    /// Connection id is sequentially generated on a first seen basis, based on TCP 4-tuple.
    /// Reverse connection id is generated at the same time
    pub connection_to_id: HashMap<TcpConnection, u32>,
    /// last generated connection Id
    pub last_connection_id: u32,
}

impl Default for PcapTcpAssembler<'_> {
    fn default() -> Self {
        PcapTcpAssembler::new(0x20000 /* 131072 == 120 K */, 100, Some(&[u32::MAX]))
    }
}

fn calculate_last_consumed_sequence_number(last_consumed_sequence_number: u32, consumed_size: u32, trace: Option<&str>) -> u32 {
    if MAX_SEQUENCE_NUMBER - last_consumed_sequence_number < consumed_size {
        if trace.is_some() {
            println!(
                "{} Rotate last_consumed_sequence_number {}",
                trace.unwrap(),
                consumed_size - (MAX_SEQUENCE_NUMBER - last_consumed_sequence_number)
            );
        }
        consumed_size - (MAX_SEQUENCE_NUMBER - last_consumed_sequence_number)
    } else {
        // if trace.is_some() {
        //     println!(
        //         "{} Update last_consumed_sequence_number {}",
        //         trace.unwrap(),
        //         last_consumed_sequence_number + consumed_size
        //     );
        // }
        last_consumed_sequence_number + consumed_size
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
                let consumed_size = consume_buffer(
                    self.trace_connections,
                    tcp_storage,
                    try_consume_tcp_payload,
                    inform_packet_loss,
                    true,
                    tcp_storage.last_consumed_sequence_number,
                );
                let trace_str = format!("[{}]:", tcp_storage.connection_id);
                tcp_storage.last_consumed_sequence_number = calculate_last_consumed_sequence_number(
                    tcp_storage.last_consumed_sequence_number,
                    consumed_size,
                    if check_trace_connection(self.trace_connections, tcp_storage.connection_id) {
                        Some(&trace_str)
                    } else {
                        None
                    },
                );
            }
        }
    }

    /// Main function for assembling TCP segments
    /// # Arguments
    /// * `logging_channel_id`: Allow to ignore duplicated packets if they are captured multiple times by logging equipment. Use-case: complex tracing setups with hardware Probes.
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
        logging_channel_id: Option<u16>,
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
        let Ok(ip_payload_len) = ipv4_header_slice.payload_len() else {
            return;
        };
        let tcp_segment_size: u32 = ip_payload_len as u32 - tcp_header_slice.data_offset() as u32 * 4;
        let with_payload =
            tcp_segment_size > 0 && (tcp_payload.len() as u32) >= tcp_segment_size && !tcp_header_slice.syn() && !tcp_header_slice.rst();

        let logging_channel_id = if logging_channel_id.is_some() { logging_channel_id.unwrap() } else { 0 };
        let tcp_connection = TcpConnection {
            source_ipv4_address: ipv4_header_slice.source().into(),
            destination_ipv4_address: ipv4_header_slice.destination().into(),
            source_port: tcp_header_slice.source_port(),
            destination_port: tcp_header_slice.destination_port(),
        };

        let mut trace_relative_sequence_number: u32 = 1;

        let mut tcp_storage_option = self.connections.get_mut(&tcp_connection);
        if logging_channel_id != 0 {
            // Ignore other logging channels duplicated packets.
            // Use packets from the logging channel, which has appeared first. It doesn't matter which one.
            // Ignore all packets from same connection on other logging channels.
            // Avoid processing of same TCP packet, captured twice.
            if tcp_storage_option.is_some() && tcp_storage_option.as_ref().unwrap().stick_to_logging_channel != logging_channel_id {
                return;
            };
        }

        // If true, then current segment sequence number has jumped over 0, while in the tcp_assembler there are still packets with sequence numbers close to MAX_SEQUENCE_NUMBER.
        // Used to calculate `payload_offset` variable.
        // After sequence number rotation, it will naturally have value false for newer segments, as soon as **all** older segments are consumed,
        // and there are no more segments left with sequence numbers, which are close to MAX_SEQUENCE_NUMBER.
        let mut sequence_number_rotated = false;

        // https://datatracker.ietf.org/doc/html/rfc7323 is not yet implemented.
        // TODO: Support TCP timestamp option TSval, TSecr to detect sequence number rotation
        // TODO: Maybe. log RTTM from timestamps
        // TODO: Maybe. Calculate and log timestamps like Wireshark: from first frame in connection, from previous frame in connection. Maybe they should be per stream.
        if with_payload && tcp_storage_option.is_some() {
            let tcp_storage = tcp_storage_option.as_deref_mut().unwrap();
            let receive_buffer_size = tcp_storage.receive_buffers.0.len();

            if tcp_header_slice.sequence_number() < tcp_storage.last_consumed_sequence_number {
                // Detect following cases:
                // 1. Sequence number rotation over 0.
                // 2. Old duplicate segment.
                //      - Segment was already seen and assembled - duplicate.
                //      - Segment arrived out of order and within threshold.
                // 3. Broken TCP connection.
                //      - Segment sequence number too far away from current receive buffer.
                //      - Out of threshold.
                // const MAX_SEQUENCE_NUMBER: u32 = u32::MAX;

                sequence_number_rotated = tcp_header_slice.sequence_number() < tcp_storage.last_consumed_sequence_number
                    && (MAX_SEQUENCE_NUMBER - tcp_storage.last_consumed_sequence_number) + tcp_header_slice.sequence_number()
                        < receive_buffer_size as u32;

                if sequence_number_rotated {
                    // Log level too high, please comment
                    trace!(
                        "[{}]: Raw sequence number rotated {}",
                        self.trace_connections,
                        tcp_storage.connection_id,
                        tcp_header_slice.sequence_number()
                    );
                    trace_relative_sequence_number = tcp_header_slice.sequence_number();

                    // Intent: Set trace_start_raw_sequence_number to zero here, because it is used for logging only of current segment.
                    tcp_storage.trace_start_raw_sequence_number = 0;
                } else {
                    let sequence_number_old_duplicate =
                        tcp_storage.last_consumed_sequence_number - tcp_header_slice.sequence_number() < SEQUENCE_NUMBER_OLD_DUPLICATE_THRESHOLD;
                    if sequence_number_old_duplicate {
                        trace!(
                            "[{}]: {} Raw sequence number is smaller, than the last_consumed_sequence_number {}, it is within 'old duplicate' threshold {}, drop segment.",
                            self.trace_connections,
                            tcp_storage.connection_id,
                            tcp_header_slice.sequence_number(),
                            tcp_storage.last_consumed_sequence_number,
                            SEQUENCE_NUMBER_OLD_DUPLICATE_THRESHOLD
                        );

                        return;
                    } else {
                        trace_relative_sequence_number = tcp_header_slice.sequence_number();
                        let log = format!(
                            "Raw sequence number is smaller, than the last_consumed_sequence_number {}, it is outside of 'old duplicate' threshold {}. ",
                            tcp_storage.last_consumed_sequence_number,
                            SEQUENCE_NUMBER_OLD_DUPLICATE_THRESHOLD
                        );
                        self.remove_connection(
                            &tcp_connection,
                            tcp_header_slice,
                            try_consume_tcp_payload,
                            inform_packet_loss,
                            trace_relative_sequence_number,
                            false,
                            log.as_str(),
                        );
                        let reversed_connection = tcp_connection.get_reverse_connection();
                        self.remove_connection(
                            &reversed_connection,
                            tcp_header_slice,
                            try_consume_tcp_payload,
                            inform_packet_loss,
                            trace_relative_sequence_number,
                            true,
                            log.as_str(),
                        );
                    }
                }
            } else {
                let sequence_number_outside_of_receive_buffer =
                    tcp_header_slice.sequence_number() - tcp_storage.last_consumed_sequence_number > receive_buffer_size as u32;
                if sequence_number_outside_of_receive_buffer {
                    let log = format!(
                        "Raw sequence number is outside of receive buffer {} + {}. ",
                        tcp_storage.last_consumed_sequence_number, receive_buffer_size
                    );
                    self.remove_connection(
                        &tcp_connection,
                        tcp_header_slice,
                        try_consume_tcp_payload,
                        inform_packet_loss,
                        trace_relative_sequence_number,
                        false,
                        log.as_str(),
                    );
                    let reversed_connection = tcp_connection.get_reverse_connection();
                    self.remove_connection(
                        &reversed_connection,
                        tcp_header_slice,
                        try_consume_tcp_payload,
                        inform_packet_loss,
                        trace_relative_sequence_number,
                        true,
                        log.as_str(),
                    );
                } else {
                    // Mainstream case.

                    // trace_start_raw_sequence_number rotation.
                    // This is reachable on a next segment after tcp_storage.last_consumed_sequence_number rotates over 0.
                    if tcp_storage.trace_start_raw_sequence_number > tcp_header_slice.sequence_number() {
                        trace!(
                            "[{}]: Rotate trace_start_raw_sequence_number 0",
                            self.trace_connections,
                            tcp_storage.connection_id,
                        );
                        tcp_storage.trace_start_raw_sequence_number = 0;
                    }

                    trace_relative_sequence_number = tcp_header_slice.sequence_number() - tcp_storage.trace_start_raw_sequence_number + 1;
                }
            }
        }

        if tcp_header_slice.rst() {
            self.remove_connection(
                &tcp_connection,
                tcp_header_slice,
                try_consume_tcp_payload,
                inform_packet_loss,
                trace_relative_sequence_number,
                false,
                "RST. ",
            );

            let reversed_connection = tcp_connection.get_reverse_connection();
            self.remove_connection(
                &reversed_connection,
                tcp_header_slice,
                try_consume_tcp_payload,
                inform_packet_loss,
                trace_relative_sequence_number,
                true,
                "RST. ",
            );

            // No payload allowed with RST flag
            return;
        } else if tcp_header_slice.syn() {
            let connection_id = self.get_connection_id(&tcp_connection);
            let tcp_flag = if tcp_header_slice.ack() { "SYN + ACK" } else { "SYN no ACK" };

            self.remove_connection(
                &tcp_connection,
                tcp_header_slice,
                try_consume_tcp_payload,
                inform_packet_loss,
                trace_relative_sequence_number,
                false,
                format!("{}. ", tcp_flag).as_str(),
            );

            if !tcp_header_slice.ack() {
                let reversed_connection = tcp_connection.get_reverse_connection();
                self.remove_connection(
                    &reversed_connection,
                    tcp_header_slice,
                    try_consume_tcp_payload,
                    inform_packet_loss,
                    trace_relative_sequence_number,
                    true,
                    format!("{}. ", tcp_flag).as_str(),
                );
            }

            trace!(
                "[{}]: {} {}, new connection, logging_channel {} {:?}",
                self.trace_connections,
                connection_id,
                trace_relative_sequence_number,
                tcp_flag,
                logging_channel_id,
                tcp_connection
            );
            self.connections.insert(
                tcp_connection.clone(),
                TcpReceiveStorage::new(
                    self.receive_buffer_size,
                    self.tcp_assembler_size,
                    tcp_connection.clone(),
                    connection_id,
                    logging_channel_id,
                    tcp_header_slice.sequence_number(),
                    true,
                ),
            );

            // No payload allowed with SYN flag
            return;
        }

        if with_payload {
            self.process_segment(
                &tcp_connection,
                logging_channel_id,
                tcp_header_slice,
                sequence_number_rotated,
                tcp_segment_size,
                trace_relative_sequence_number,
                inform_packet_loss,
                try_consume_tcp_payload,
                tcp_payload,
            );
        }

        if tcp_header_slice.fin() {
            self.remove_connection(
                &tcp_connection,
                tcp_header_slice,
                try_consume_tcp_payload,
                inform_packet_loss,
                trace_relative_sequence_number,
                false,
                "FIN. ",
            );

            let reversed_connection = tcp_connection.get_reverse_connection();
            self.remove_connection(
                &reversed_connection,
                tcp_header_slice,
                try_consume_tcp_payload,
                inform_packet_loss,
                trace_relative_sequence_number,
                true,
                "FIN. ",
            );
        }
    }

    fn remove_connection(
        &mut self,
        tcp_connection: &TcpConnection,
        tcp_header_slice: &TcpHeaderSlice,
        try_consume_tcp_payload: &mut dyn FnMut(&[u8], u32, &TcpConnection, Option<&str>) -> u32,
        inform_packet_loss: &mut dyn FnMut(u32, &TcpConnection, u32, Option<&str>),
        trace_relative_sequence_number: u32,
        reverse_connection: bool,
        log: &str,
    ) {
        if let Some(mut removed_storage) = self.connections.shift_remove(tcp_connection) {
            trace!(
                "[{}]: {} {}{}",
                self.trace_connections,
                removed_storage.connection_id,
                if reverse_connection {
                    removed_storage.last_consumed_sequence_number - removed_storage.trace_start_raw_sequence_number
                } else {
                    tcp_header_slice.sequence_number()
                },
                log,
                if reverse_connection {
                    "Remove reverse connection."
                } else {
                    "Remove connection."
                }
            );

            while removed_storage.tcp_assembler.len() > 0 {
                let consumed_size = consume_buffer(
                    self.trace_connections,
                    &mut removed_storage,
                    try_consume_tcp_payload,
                    inform_packet_loss,
                    true,
                    trace_relative_sequence_number,
                );
                let trace_str = format!("[{}]:", removed_storage.connection_id);
                removed_storage.last_consumed_sequence_number = calculate_last_consumed_sequence_number(
                    removed_storage.last_consumed_sequence_number,
                    consumed_size,
                    if check_trace_connection(self.trace_connections, removed_storage.connection_id) {
                        Some(&trace_str)
                    } else {
                        None
                    },
                );
            }
        }
    }

    fn process_segment(
        &mut self,
        tcp_connection: &TcpConnection,
        logging_channel_id: u16,
        tcp_header_slice: &TcpHeaderSlice,
        sequence_number_rotated: bool,
        tcp_segment_size: u32,
        trace_relative_sequence_number: u32,
        inform_packet_loss: &mut dyn FnMut(u32, &TcpConnection, u32, Option<&str>),
        try_consume_tcp_payload: &mut dyn FnMut(&[u8], u32, &TcpConnection, Option<&str>) -> u32,
        tcp_payload: &[u8],
    ) {
        let connection_id = self.get_connection_id(tcp_connection);
        let tcp_storage = self.connections.entry(tcp_connection.clone()).or_insert_with(|| {
            let new_tcp_storage = TcpReceiveStorage::new(
                self.receive_buffer_size,
                self.tcp_assembler_size,
                tcp_connection.clone(),
                connection_id,
                logging_channel_id,
                tcp_header_slice.sequence_number(),
                false,
            );
            trace!(
                "[{}]: {}/{} No SYN, new connection, logging channel {} {:?}",
                self.trace_connections,
                connection_id,
                trace_relative_sequence_number,
                tcp_header_slice.sequence_number(),
                logging_channel_id,
                tcp_connection
            );

            new_tcp_storage
        });

        let mut payload_offset = if sequence_number_rotated {
            (MAX_SEQUENCE_NUMBER - tcp_storage.last_consumed_sequence_number) + tcp_header_slice.sequence_number()
        } else {
            tcp_header_slice.sequence_number() - tcp_storage.last_consumed_sequence_number
        };

        // Segment does not fit to the `receive_buffer`. Buffer is full. Force to consume.
        while payload_offset + tcp_segment_size > self.receive_buffer_size as u32 {
            if tcp_storage.tcp_assembler.len() == 0 {
                let trace_str = format!("[{}]: {}", tcp_storage.connection_id, trace_relative_sequence_number);
                inform_packet_loss(
                    tcp_storage.connection_id,
                    tcp_connection,
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
            let consumed_size = consume_buffer(
                self.trace_connections,
                tcp_storage,
                try_consume_tcp_payload,
                inform_packet_loss,
                true,
                trace_relative_sequence_number,
            );
            let trace_str = format!("[{}]:", tcp_storage.connection_id);
            tcp_storage.last_consumed_sequence_number = calculate_last_consumed_sequence_number(
                tcp_storage.last_consumed_sequence_number,
                consumed_size,
                if check_trace_connection(self.trace_connections, tcp_storage.connection_id) {
                    Some(&trace_str)
                } else {
                    None
                },
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
        if tcp_assembler.peek_front() != 0 {
            // Mainstream use-case. Try to consume as soon as segment received.
            let consumed_size = consume_buffer(
                self.trace_connections,
                tcp_storage,
                try_consume_tcp_payload,
                inform_packet_loss,
                false,
                trace_relative_sequence_number,
            );
            let trace_str = format!("[{}]:", tcp_storage.connection_id);
            tcp_storage.last_consumed_sequence_number = calculate_last_consumed_sequence_number(
                tcp_storage.last_consumed_sequence_number,
                consumed_size,
                if check_trace_connection(self.trace_connections, tcp_storage.connection_id) {
                    Some(&trace_str)
                } else {
                    None
                },
            );
        }
    }
}
