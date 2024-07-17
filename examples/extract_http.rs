/*
 * @copyright (C) 2024 Ruslan Iusupov <https://github.com/rus0000>
 *
 * SPDX-License-Identifier: MIT
 */
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;

use etherparse::{ether_type::IPV4, Ethernet2HeaderSlice, IpNumber, Ipv4HeaderSlice, TcpHeaderSlice};
use httparse;
use rpcap::{read::PcapReader, CapturedPacket};

use pcap_tcp_assembler::PcapTcpAssembler;

#[derive(Default)]
struct HttpMessage {
    is_request: bool,
    content_length: usize,
    chunked_encoding: bool,
    headers_buffer: Vec<u8>,
    headers: Vec<(String, String)>,
    headers_size_bytes: usize,
    body: Vec<u8>,
    headers_received: bool,
    current_chunk: Vec<u8>,
    tcp_trace: Option<String>,
    http_trace: String,
}

fn parse_packet<'a>(captured_packet: &'a CapturedPacket<'a>) -> Option<(Ipv4HeaderSlice<'a>, TcpHeaderSlice<'a>, &'a [u8])> {
    let Ok(ethernet_header_slice) = Ethernet2HeaderSlice::from_slice(captured_packet.data) else {
        eprintln!("Cannot parse Ethernet header");
        return None;
    };
    if ethernet_header_slice.ether_type() != IPV4 {
        return None;
    }
    let ethernet_header_size = ethernet_header_slice.slice().len();
    let ethernet_payload = &captured_packet.data[ethernet_header_size..];

    // Assume no MACsec, no VLANs
    let Ok(ipv4_header_slice) = Ipv4HeaderSlice::from_slice(ethernet_payload) else {
        eprintln!("Cannot parse IPv4 header");
        return None;
    };
    if ipv4_header_slice.protocol() != IpNumber::Tcp as u8 {
        return None;
    }
    let ipv4_header_size = ipv4_header_slice.slice().len();
    let ipv4_payload = &ethernet_payload[ipv4_header_size..ipv4_header_slice.total_len() as usize];

    // Assume no AH
    let Ok(tcp_header_slice) = TcpHeaderSlice::from_slice(&ipv4_payload) else {
        eprintln!("Cannot parse TCP header");
        return None;
    };
    let tcp_header_size = tcp_header_slice.slice().len();
    let tcp_payload = &ipv4_payload[tcp_header_size..];

    Some((ipv4_header_slice, tcp_header_slice, tcp_payload))
}

fn consume_chunked_encoding_body(http_message: &mut HttpMessage, consumable_tcp_payload: &[u8]) -> (usize, bool) {
    let chunk_old_size = http_message.current_chunk.len();
    http_message.current_chunk.extend_from_slice(consumable_tcp_payload);

    // How much of consumable_tcp_payload is consumed
    let mut consumed_size: usize = 0;

    while consumed_size < consumable_tcp_payload.len() {
        if let Ok(status) = httparse::parse_chunk_size(&http_message.current_chunk) {
            if status.is_complete() {
                let (index, size) = status.unwrap();
                // End chunk is zero sized
                if size == 0 {
                    let body_str = if http_message
                        .headers
                        .iter()
                        .find(|header| header.0 == "Content-Type" && header.1.starts_with("text"))
                        .is_some()
                    {
                        std::str::from_utf8(&http_message.body).unwrap().to_owned()
                    } else {
                        format!("{:X?}", http_message.body)
                    };
                    if http_message.tcp_trace.is_some() {
                        println!(
                            "{} >>> http: {} body complete {} bytes, reset http message \n{}\n",
                            http_message.tcp_trace.as_deref().unwrap(),
                            http_message.http_trace,
                            http_message.body.len(),
                            &body_str[..100],
                        );
                    }

                    http_message.current_chunk.clear();

                    // 0/r/n/r/n
                    return (consumed_size + 5, true);
                } else {
                    // Chunk body fully contained in the http_message.current_chunk
                    // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Transfer-Encoding#directives
                    // + 2 is a delimiter \r\n at end of the chunk
                    let full_chunk_size = index + size as usize + 2;
                    if http_message.current_chunk.len() >= full_chunk_size {
                        consumed_size += full_chunk_size - chunk_old_size;
                        http_message
                            .body
                            .extend_from_slice(&http_message.current_chunk[index..index + size as usize]);

                        if full_chunk_size == http_message.current_chunk.len() {
                            // Chunk is fully consumed in this payload, but there are other in next TCP payload.
                            return (consumed_size, false);
                        }

                        http_message.current_chunk.drain(..full_chunk_size);

                        // Chunk size was not 0, so body is not finished.
                        // try next chunk in this payload
                        continue;
                    } else {
                        if http_message.tcp_trace.is_some() {
                            println!(
                                "{} >>> http: {} body consumed {} bytes",
                                http_message.tcp_trace.as_deref().unwrap(),
                                http_message.http_trace,
                                consumable_tcp_payload.len()
                            );
                        }

                        // Chunk will continue in next TCP payload
                        return (consumable_tcp_payload.len(), false);
                    }
                }
            } else {
                // Chunk header is incomplete.
                if http_message.tcp_trace.is_some() {
                    println!(
                        "{} >>> http: {} body consumed {} bytes",
                        http_message.tcp_trace.as_deref().unwrap(),
                        http_message.http_trace,
                        consumable_tcp_payload.len()
                    );
                }

                // Chunk will continue in next TCP payload
                return (consumable_tcp_payload.len(), false);
            }
        } else {
            // Error, reset http message
            return (0, true);
        }
    }
    unreachable!();
}

fn consume_content_length_body(http_message: &mut HttpMessage, consumable_tcp_payload: &[u8]) -> (usize, bool) {
    let mut message_complete = false;
    let mut remaining_body_bytes = http_message.content_length - http_message.body.len();
    if remaining_body_bytes > consumable_tcp_payload.len() {
        remaining_body_bytes = consumable_tcp_payload.len();
    }
    http_message.body.extend_from_slice(&consumable_tcp_payload[..remaining_body_bytes]);

    if http_message.content_length == http_message.body.len() {
        if http_message.tcp_trace.is_some() {
            let body_str = if http_message
                .headers
                .iter()
                .find(|header| header.0 == "Content-Type" && header.1.starts_with("text"))
                .is_some()
            {
                std::str::from_utf8(&http_message.body).unwrap().to_owned()
            } else {
                format!("{:X?}", http_message.body)
            };

            println!(
                "{} >>> http: {} body complete {} bytes, reset http message \n{}\n",
                http_message.tcp_trace.as_deref().unwrap(),
                http_message.http_trace,
                http_message.body.len(),
                &body_str[..100],
            );
        }
        message_complete = true;
    } else {
        if http_message.tcp_trace.is_some() {
            println!(
                "{} >>> http: {} body consumed {} bytes",
                http_message.tcp_trace.as_deref().unwrap(),
                http_message.http_trace,
                remaining_body_bytes
            );
        }
    }

    (remaining_body_bytes, message_complete)
}

fn consume_body(http_message: &mut HttpMessage, consumable_tcp_payload: &[u8]) -> (usize, bool) {
    if http_message.content_length > 0 {
        consume_content_length_body(http_message, consumable_tcp_payload)
    } else if http_message.chunked_encoding {
        consume_chunked_encoding_body(http_message, consumable_tcp_payload)
    } else {
        if http_message.tcp_trace.is_some() {
            println!(
                "{} >>> http: {} complete, no body, reset http message",
                http_message.tcp_trace.as_deref().unwrap(),
                http_message.http_trace
            );
        }

        (0, true)
    }
}

fn try_consume_tcp_payload(http_message: &mut HttpMessage, consumable_tcp_payload: &[u8], tcp_trace: Option<&str>) -> (u32, bool) {
    http_message.tcp_trace = if tcp_trace.is_some() {
        Some(tcp_trace.unwrap().to_owned())
    } else {
        None
    };

    // TCP segment without HTTP headers, not a first segment. Contains only body bytes.
    if http_message.headers_received {
        let (consumed_size, message_complete) = consume_body(http_message, consumable_tcp_payload);

        return (consumed_size as u32, message_complete);
    }

    // Response is tried when message is not a request or message is not yet known and request parsing has failed.
    let mut should_try_response = false;

    let should_try_request = http_message.headers_buffer.len() == 0 || http_message.is_request;

    if should_try_request {
        let headers_buffer = &mut http_message.headers_buffer;

        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut request = httparse::Request::new(&mut headers);
        // Beginning of message should be always recognized from consumable_tcp_payload. If payload is too short, then no chance.
        let status = if headers_buffer.is_empty() {
            request.parse(&consumable_tcp_payload)
        } else {
            // Headers are processed, only when all header bytes are received in the headers_buffer.
            headers_buffer.extend_from_slice(consumable_tcp_payload);
            request.parse(&headers_buffer)
        };

        if status.is_ok() {
            http_message.is_request = true;
            http_message.http_trace = "request".to_owned();
            if status.unwrap().is_complete() {
                http_message.headers_received = true;
                for header in request.headers.iter() {
                    let header_value = std::str::from_utf8(header.value);
                    if header_value.is_ok() {
                        http_message.headers.push((header.name.to_owned(), header_value.unwrap().to_owned()));
                    }
                }
                http_message.headers_size_bytes = status.unwrap().unwrap();

                if tcp_trace.is_some() {
                    println!(
                        "{} >>> http: request {} {}",
                        &tcp_trace.unwrap(),
                        request.method.unwrap_or_default(),
                        request.path.unwrap_or_default()
                    );
                    println!(
                        "{} >>> http: {} headers {} bytes {:?}",
                        http_message.tcp_trace.as_deref().unwrap(),
                        http_message.http_trace,
                        http_message.headers_size_bytes,
                        http_message.headers
                    );
                }

                let consumed_headers_size = if headers_buffer.is_empty() {
                    http_message.headers_size_bytes
                } else {
                    headers_buffer.len() - http_message.headers_size_bytes
                };

                headers_buffer.clear();

                // Rest of consumable_tcp_payload could be a HTTP message body.
                let (consumed_body_size, message_complete) = consume_body(http_message, &consumable_tcp_payload[consumed_headers_size..]);

                return (consumed_headers_size as u32 + consumed_body_size as u32, message_complete);
            } else {
                if headers_buffer.is_empty() {
                    headers_buffer.extend_from_slice(consumable_tcp_payload);
                }

                return (consumable_tcp_payload.len() as u32, false);
            }
        }
        should_try_response = true;
    }
    if should_try_response {
        let headers_buffer = &mut http_message.headers_buffer;
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut response = httparse::Response::new(&mut headers);
        // Beginning of message should be recognized from given slice
        let status = if headers_buffer.is_empty() {
            response.parse(&consumable_tcp_payload)
        } else {
            headers_buffer.extend_from_slice(consumable_tcp_payload);
            response.parse(&headers_buffer)
        };

        if status.is_ok() {
            http_message.is_request = false;
            http_message.http_trace = "response".to_owned();
            if status.unwrap().is_complete() {
                http_message.headers_received = true;
                for header in response.headers {
                    let header_value = std::str::from_utf8(header.value);
                    if header_value.is_ok() {
                        http_message.headers.push((header.name.to_owned(), header_value.unwrap().to_owned()));
                        if header.name == "Content-Length" {
                            http_message.content_length = header_value.unwrap().parse::<usize>().unwrap();
                        } else if header.name == "Transfer-Encoding" && header_value.unwrap() == "chunked" {
                            http_message.chunked_encoding = true;
                        }
                    }
                }
                http_message.headers_size_bytes = status.unwrap().unwrap();

                if tcp_trace.is_some() {
                    println!(
                        "{} >>> http: response {} {}",
                        &tcp_trace.unwrap(),
                        response.code.unwrap_or_default(),
                        response.reason.unwrap_or_default()
                    );
                    println!(
                        "{} >>> http: {} headers {} bytes {:?}",
                        http_message.tcp_trace.as_deref().unwrap(),
                        http_message.http_trace,
                        http_message.headers_size_bytes,
                        http_message.headers
                    );
                }

                let consumed_headers_size = if headers_buffer.is_empty() {
                    http_message.headers_size_bytes
                } else {
                    headers_buffer.len() - http_message.headers_size_bytes
                };

                headers_buffer.clear();

                let (consumed_body_size, message_complete) = consume_body(http_message, &consumable_tcp_payload[consumed_headers_size..]);

                return (consumed_headers_size as u32 + consumed_body_size as u32, message_complete);
            } else {
                if headers_buffer.is_empty() {
                    headers_buffer.extend_from_slice(consumable_tcp_payload);
                }

                return (consumable_tcp_payload.len() as u32, false);
            }
        } else {
            if tcp_trace.is_some() {
                println!("{} >>> http: cannot parse headers, reset http message", &tcp_trace.unwrap());
            }

            return (0, true);
        }
    }

    unreachable!();
}

/**
 * Extract HTTP from segmented TCP stream in PCAP
 * PCAPNG is not supported by rpcap, please use `pcap_parser` crate if it is needed.
 *
 * cargo run --example extract_http .\examples\segmented_tcp2.pcap
 */
fn main() {
    // Receive one HttpMessage at a time per each TCP connection. Therefore two at a time per TCP session.
    let mut connection_id_to_http_message = HashMap::<u32, HttpMessage>::new();
    let pcap_file_name = std::env::args().nth(1).expect("Expect path to PCAP file");

    let buf_reader = BufReader::new(File::open(pcap_file_name).expect("Cannot read file"));
    let (_, mut pcap_reader) = PcapReader::new(buf_reader).expect("Cannot read pcap");
    let mut pcap_tcp_assembler = PcapTcpAssembler::new(0x20000 /* 131072 == 120 K */, 100, Some(&[]));
    let mut reset_connection_id = 0;

    while let Some(captured_packet) = pcap_reader.next().unwrap() {
        let Some((ipv4_header_slice, tcp_header_slice, tcp_payload)) = parse_packet(&captured_packet) else {
            continue;
        };
        if reset_connection_id > 0 {
            connection_id_to_http_message.remove(&reset_connection_id);
            reset_connection_id = 0;
        }

        pcap_tcp_assembler.handle_segment(
            None,
            &ipv4_header_slice,
            &tcp_header_slice,
            tcp_payload,
            &mut |consumable_tcp_payload, connection_id, _tcp_connection, trace| {
                let http_message = connection_id_to_http_message.entry(connection_id).or_default();
                let (consumed_body_size, message_complete) = try_consume_tcp_payload(http_message, consumable_tcp_payload, trace);
                if message_complete {
                    connection_id_to_http_message.remove(&connection_id);
                }
                consumed_body_size
            },
            &mut |connection_id, tcp_connection, lost_bytes, trace| {
                if trace.is_some() {
                    println!(
                        "{} capture packet loss: {} bytes {:?}, reset http message",
                        trace.unwrap(),
                        lost_bytes,
                        tcp_connection,
                    );
                }
                reset_connection_id = connection_id;
            },
        )
    }

    pcap_tcp_assembler.consume_all_buffers(
        &mut |consumable_tcp_payload, connection_id, _tcp_connection, trace| {
            let http_message = connection_id_to_http_message.entry(connection_id).or_default();
            let (consumed_body_size, message_complete) = try_consume_tcp_payload(http_message, consumable_tcp_payload, trace);
            if message_complete {
                connection_id_to_http_message.remove(&connection_id);
            }
            consumed_body_size
        },
        &mut |connection_id, tcp_connection, lost_bytes, trace| {
            if trace.is_some() {
                println!(
                    "{} capture packet loss: {} bytes {:?}, reset http message",
                    trace.unwrap(),
                    lost_bytes,
                    tcp_connection,
                );
            }
            reset_connection_id = connection_id;
        },
    );
}
