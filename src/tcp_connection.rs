/*
 * @copyright (C) 2024 Ruslan Iusupov <https://github.com/rus0000>
 *
 * SPDX-License-Identifier: MIT
 */
use std::fmt;
use std::net::Ipv4Addr;

/// TCP connection Four-tuple: two IPs + two ports. Traffic in one direction only.
/// TCP session consist of two TCP connections in two directions.
/// Assumption, that IP Addresses are unique per VLAN, so VLAN is excluded from TCP connection tuple.
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone)]
pub struct TcpConnection {
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_default() {
        let tcp_connection = TcpConnection::default();
        assert_eq!(
            tcp_connection,
            TcpConnection {
                source_ipv4_address: [0, 0, 0, 0].into(),
                source_port: 0,
                destination_ipv4_address: [0, 0, 0, 0].into(),
                destination_port: 0,
            }
        );
    }
    #[test]
    fn test_get_reverse_connection() {
        let tcp_connection = TcpConnection {
            source_ipv4_address: [1, 2, 3, 4].into(),
            source_port: 1234,
            destination_ipv4_address: [4, 3, 2, 1].into(),
            destination_port: 4321,
        };
        assert_eq!(
            tcp_connection.get_reverse_connection(),
            TcpConnection {
                source_ipv4_address: [4, 3, 2, 1].into(),
                source_port: 4321,
                destination_ipv4_address: [1, 2, 3, 4].into(),
                destination_port: 1234,
            }
        );
    }
    #[test]
    fn test_fmt_debug() {
        let tcp_connection = TcpConnection::default();
        assert_eq!(
            format!("{:?}", tcp_connection),
            "(ip.addr == 0.0.0.0 && ip.addr == 0.0.0.0 && tcp.port == 0 && tcp.port == 0)"
        );
    }
}
