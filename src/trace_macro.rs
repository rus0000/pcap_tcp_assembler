/*
 * @copyright (C) 2024 Ruslan Iusupov <https://github.com/rus0000>
 *
 * SPDX-License-Identifier: MIT
 */

pub fn check_trace_connection(trace_connections: &[u32], connection_id: u32) -> bool {
    trace_connections.contains(&connection_id) || trace_connections.len() == 0
}

#[macro_export]
macro_rules! trace {
    ($format_pattern: expr, $trace_connections: expr, $connection_id: expr, $($arg: expr),*) => {
        if check_trace_connection($trace_connections, $connection_id) {
            println!($format_pattern, $connection_id, $($arg),*);
        };
    }
}
