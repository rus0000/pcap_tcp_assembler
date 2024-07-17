/*
 * @copyright (C) 2024 Ruslan Iusupov <https://github.com/rus0000>
 *
 * SPDX-License-Identifier: MIT
 */

use crate::{tcp_connection::TcpConnection, tcp_receive_storage::TcpReceiveStorage, trace, trace_macro::check_trace_connection};

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
            "[{}]: {} consume_buffer() force_to_consume",
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
            // trace!(
            //     "[{}]: {} consume_buffer() force_to_consume - try to consume {} bytes",
            //     trace_connections,
            //     tcp_storage.connection_id,
            //     trace_relative_sequence_number,
            //     data_iter
            // );
            if consumed_size > 0 {
                let remove_from_buffer = data_iter as u32 + consumed_size;
                if tcp_storage.tcp_assembler.remove_data_at_head(remove_from_buffer as usize).is_err() {
                    trace!(
                        "[{}]: consume_buffer() force_to_consume - remove_data_at_head panic: {} {}",
                        trace_connections,
                        tcp_storage.connection_id,
                        leading_hole_size,
                        consumed_size
                    );
                    panic!();
                }

                trace!(
                    "[{}]: {} consume_buffer() force_to_consume - consumed {} bytes, dropped {} bytes",
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
                    "[{}]: {} consume_buffer() force_to_consume - copy_buffer {} bytes_on_right {} ",
                    trace_connections,
                    tcp_storage.connection_id,
                    trace_relative_sequence_number,
                    data_iter + consumed_size as usize,
                    bytes_on_right
                );
                tcp_storage.current_receive_buffer = copy_buffer(tcp_storage, data_iter + consumed_size as usize, bytes_on_right);
                // trace!(
                //     "[{}]: {} consume_buffer() force_to_consume - receive buffer still has: {} bytes",
                //     trace_connections,
                //     tcp_storage.connection_id,
                //     trace_relative_sequence_number,
                //     bytes_on_right
                // );

                return remove_from_buffer;
            }
        }
        // Whole first continuous range is garbage.
        if tcp_storage.tcp_assembler.remove_data_at_head(data_end).is_err() {
            trace!(
                "[{}]: consume_buffer() force_to_consume - remove_data_at_head panic: {}",
                trace_connections,
                tcp_storage.connection_id,
                data_end
            );
            panic!();
        }
        trace!(
            "[{}]: {} consume_buffer() force_to_consume - remove_data_at_head {}",
            trace_connections,
            tcp_storage.connection_id,
            trace_relative_sequence_number,
            data_end
        );

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
