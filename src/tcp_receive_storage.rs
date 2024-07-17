/*
 * @copyright (C) 2024 Ruslan Iusupov <https://github.com/rus0000>
 *
 * SPDX-License-Identifier: MIT
 */
 use crate::{assembler::Assembler, tcp_connection::TcpConnection};

/// Allocated 2x times per each TCP connection. One in each direction: source -> destination.
#[derive(Debug)]
pub struct TcpReceiveStorage {
    /// * Immutable.
    pub tcp_connection: TcpConnection,
    /// * Immutable.
    pub connection_id: u32,

    /// Avoid processing of same TCP packet, captured twice.
    /// * Immutable.
    pub stick_to_logging_channel: u16,
    /// * Immutable.
    pub tcp_assembler: Assembler,

    /// Pre-allocated receive buffers, A and B.
    /// * Mutable.
    pub receive_buffers: (Vec<u8>, Vec<u8>),

    /// 0 == A, 1 == B in receive_buffers
    /// * Mutable.
    pub current_receive_buffer: u8,

    /// Raw sequence number from first segment in this TCP connection. Not necessarily ISN.
    /// * Mutable.
    /// * Used only for tracing purposes.
    /// * Could be rotated and set to 0, when sequence number goes over MAX_SEQUENCE_NUMBER.
    pub trace_start_raw_sequence_number: u32,

    /// Raw sequence number. Denotes the first byte in active receive_buffer.
    /// * Mutable.
    /// * Incremented as bytes are consumed by the application.
    /// * Could be rotated and start from 0, when value goes over MAX_SEQUENCE_NUMBER.
    ///
    /// Concept of operation:
    /// * The size of buffered, but not yet consumed data is held by `tcp_assembler`. It includes holes and data.
    /// * This member is used to calculate position of received TCP segment inside of `tcp_assembler`.
    /// * See `payload_offset` and `sequence_number_rotated` variables.
    /// * `tcp_assembler` does not operates with any sequence numbers, neither absolute (raw) nor relative.
    /// * `tcp_assembler` holds only sizes of contigs.
    /// * See [TcpReceiveStorage::new()].
    pub last_consumed_sequence_number: u32,
}

impl TcpReceiveStorage {
    pub fn new(
        receive_buffer_size: usize,
        tcp_assembler_size: usize,
        tcp_connection: TcpConnection,
        connection_id: u32,
        logging_channel_id: u16,
        // Not necessarily ISN. Connection could start not with SYN packet.
        start_sequence_number: u32,
        is_syn: bool,
    ) -> Self {
        Self {
            tcp_connection,
            connection_id,
            stick_to_logging_channel: logging_channel_id,
            tcp_assembler: Assembler::new(tcp_assembler_size),
            receive_buffers: (vec![0; receive_buffer_size], vec![0; receive_buffer_size]),
            current_receive_buffer: 0,
            trace_start_raw_sequence_number: start_sequence_number,
            last_consumed_sequence_number: if is_syn { start_sequence_number + 1 } else { start_sequence_number },
            // last_buffered_sequence_number: 0,
            // sequence_number_to_segment_size: IndexMap::<u32, u32>::new(),
        }
    }
}
