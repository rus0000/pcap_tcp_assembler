/*
 * @copyright (C) 2024 Ruslan Iusupov <https://github.com/rus0000>
 *
 * SPDX-License-Identifier: MIT
 */
use etherparse::{IpNumber, Ipv4Header, Ipv4HeaderSlice, TcpHeader, TcpHeaderSlice};
// Rng is used only for TCP payload, it will not introduce tests flakiness
use rand::Rng;
use std::io::BufWriter;

const RECEIVE_BUFFER_SIZE: usize = 0xFFFF;
const TCP_ASSEMBLER_SIZE: usize = 10;

use pcap_tcp_assembler::{PcapTcpAssembler, TcpConnection};

fn generate_headers_buffers(sequence_number: u32, tcp_payload: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut tcp_header_buf = BufWriter::new(Vec::new());
    let tcp_header = TcpHeader::new(1000, 80, sequence_number, 65535);
    tcp_header.write(&mut tcp_header_buf).unwrap();
    let mut tcp_header_buf = tcp_header_buf.into_inner().unwrap();
    tcp_header_buf.extend_from_slice(&tcp_payload);

    let mut ipv4_header_buf = BufWriter::new(Vec::new());
    let ipv4_header = Ipv4Header::new(tcp_header_buf.len() as u16, 64, IpNumber::Tcp as u8, [192, 168, 1, 1], [192, 168, 1, 2]);
    ipv4_header.write(&mut ipv4_header_buf).unwrap();
    let ipv4_header_buf = ipv4_header_buf.into_inner().unwrap();

    (ipv4_header_buf, tcp_header_buf)
}

#[test]
fn test_it_works() {
    let mut rng = rand::thread_rng();
    let tcp_payload: [u8; 10] = core::array::from_fn(|_| rng.gen::<u8>());
    let (ipv4_header_buf, tcp_header_buf) = generate_headers_buffers(1, &tcp_payload);
    let ipv4_header_slice = Ipv4HeaderSlice::from_slice(&ipv4_header_buf).unwrap();
    let tcp_header_slice = TcpHeaderSlice::from_slice(&tcp_header_buf).unwrap();

    let mut pcap_tcp_assembler = PcapTcpAssembler::new(RECEIVE_BUFFER_SIZE, TCP_ASSEMBLER_SIZE, Some(&[]));
    pcap_tcp_assembler.handle_segment(
        None,
        &ipv4_header_slice,
        &tcp_header_slice,
        &tcp_payload,
        &mut |consumable_tcp_payload, _connection_id, _tcp_connection, _trace| {
            assert_eq!(consumable_tcp_payload, tcp_payload);
            10
        },
        &mut |_connection_id, _tcp_connection, _lost_bytes, _trace| {},
    );
}
#[test]
fn test_small_messages() {
    let mut rng = rand::thread_rng();
    let mut pcap_tcp_assembler = PcapTcpAssembler::new(RECEIVE_BUFFER_SIZE, TCP_ASSEMBLER_SIZE, Some(&[]));
    for i in 1..1000 {
        let tcp_payload: [u8; 10] = core::array::from_fn(|_| rng.gen::<u8>());
        let (ipv4_header_buf, tcp_header_buf) = generate_headers_buffers(i * 10, &tcp_payload);
        let ipv4_header_slice = Ipv4HeaderSlice::from_slice(&ipv4_header_buf).unwrap();
        let tcp_header_slice = TcpHeaderSlice::from_slice(&tcp_header_buf).unwrap();

        pcap_tcp_assembler.handle_segment(
            None,
            &ipv4_header_slice,
            &tcp_header_slice,
            &tcp_payload,
            &mut |consumable_tcp_payload, _connection_id, _tcp_connection, _trace| {
                assert_eq!(consumable_tcp_payload, tcp_payload);

                consumable_tcp_payload.len() as u32
            },
            &mut |_connection_id, _tcp_connection, _lost_bytes, _trace| {},
        )
    }
}
#[test]
fn test_chunked_messages() {
    let mut rng = rand::thread_rng();
    let mut pcap_tcp_assembler = PcapTcpAssembler::new(RECEIVE_BUFFER_SIZE, TCP_ASSEMBLER_SIZE, Some(&[]));
    let mut sequence_number = 1;
    const MAX_TCP_SEGMENT_SIZE: usize = 1460;
    const APPLICATION_MESSAGE_SIZE: usize = MAX_TCP_SEGMENT_SIZE * 10 + 10;
    const AMOUNT_OF_MESSAGES: usize = 100;

    for _ in 0..AMOUNT_OF_MESSAGES {
        let application_message: Vec<u8> = (0..APPLICATION_MESSAGE_SIZE).map(|_| rng.gen::<u8>()).collect();
        let mut message_segmentation_pointer: usize = 0;

        while message_segmentation_pointer < application_message.len() {
            let tcp_segment_size = if application_message.len() - message_segmentation_pointer > MAX_TCP_SEGMENT_SIZE {
                MAX_TCP_SEGMENT_SIZE
            } else {
                application_message.len() - message_segmentation_pointer
            };
            let tcp_payload = &application_message[message_segmentation_pointer..message_segmentation_pointer + tcp_segment_size];
            message_segmentation_pointer += tcp_segment_size;

            let (ipv4_header_buf, tcp_header_buf) = generate_headers_buffers(sequence_number as u32, &tcp_payload);
            sequence_number += tcp_segment_size;
            let ipv4_header_slice = Ipv4HeaderSlice::from_slice(&ipv4_header_buf).unwrap();
            let tcp_header_slice = TcpHeaderSlice::from_slice(&tcp_header_buf).unwrap();

            pcap_tcp_assembler.handle_segment(
                None,
                &ipv4_header_slice,
                &tcp_header_slice,
                &tcp_payload,
                &mut |consumable_tcp_payload, _connection_id, _tcp_connection, _trace| {
                    if consumable_tcp_payload.len() == application_message.len() {
                        assert_eq!(consumable_tcp_payload, application_message);

                        consumable_tcp_payload.len() as u32
                    } else {
                        0
                    }
                },
                &mut |_connection_id, tcp_connection, lost_bytes, trace| {
                    if trace.is_some() {
                        println!("{} test - capture packet loss {} bytes {:?}", trace.unwrap(), lost_bytes, tcp_connection,);
                    }
                },
            )
        }
    }
    pcap_tcp_assembler.consume_all_buffers(
        &mut |consumable_tcp_payload, _connection_id, tcp_connection, trace| {
            println!(
                "{} test - receive_buffer is not empty {} bytes {:?}",
                trace.unwrap(),
                consumable_tcp_payload.len(),
                tcp_connection,
            );
            assert_eq!(consumable_tcp_payload.len(), 0);
            0
        },
        &mut |_connection_id, tcp_connection, lost_bytes, trace| {
            if trace.is_some() {
                println!("{} test - capture packet loss {} bytes {:?}", trace.unwrap(), lost_bytes, tcp_connection,);
            }
        },
    );
}

fn messages_cross_segments(message_size: usize) {
    // Message border and TCP segment border are not aligned.
    // This case would lead to data copying between receive buffers after consuming.
    let mut rng = rand::thread_rng();
    let mut pcap_tcp_assembler = PcapTcpAssembler::new(RECEIVE_BUFFER_SIZE, TCP_ASSEMBLER_SIZE, Some(&[]));
    let mut sequence_number = 1;
    const MAX_TCP_SEGMENT_SIZE: usize = 1460;
    let amount_of_messages: usize = RECEIVE_BUFFER_SIZE * 2 / message_size;

    let mut application_messages = Vec::<Vec<u8>>::new();
    let mut byte_stream = Vec::<u8>::new();
    for _ in 0..amount_of_messages {
        let application_message: Vec<u8> = (0..message_size).map(|_| rng.gen::<u8>()).collect();
        byte_stream.extend_from_slice(&application_message);
        application_messages.push(application_message);
    }

    let mut next_message: usize = 0;
    let try_consume_tcp_payload = &mut |consumable_tcp_payload: &[u8], trace: Option<&str>| -> u32 {
        if consumable_tcp_payload.len() < message_size {
            return 0;
        }

        //
        // IMPORTANT. Consume as much of consumable_tcp_payload as possible!
        //
        let mut payload_segmentation_pointer: usize = 0;
        let mut consumed_messages = 0;
        while payload_segmentation_pointer + message_size <= consumable_tcp_payload.len() {
            assert_eq!(
                &consumable_tcp_payload[payload_segmentation_pointer..payload_segmentation_pointer + message_size],
                application_messages[next_message]
            );
            payload_segmentation_pointer += message_size;
            next_message += 1;
            consumed_messages += 1;
        }
        if trace.is_some() {
            println!("{} test - consumed_messages {}  ", trace.unwrap(), consumed_messages);
        }

        payload_segmentation_pointer as u32
    };

    let mut message_segmentation_pointer: usize = 0;
    while message_segmentation_pointer < byte_stream.len() {
        let tcp_segment_size = if byte_stream.len() - message_segmentation_pointer > MAX_TCP_SEGMENT_SIZE {
            MAX_TCP_SEGMENT_SIZE
        } else {
            byte_stream.len() - message_segmentation_pointer
        };
        let tcp_payload = &byte_stream[message_segmentation_pointer..message_segmentation_pointer + tcp_segment_size];
        message_segmentation_pointer += tcp_segment_size;

        let (ipv4_header_buf, tcp_header_buf) = generate_headers_buffers(sequence_number as u32, &tcp_payload);
        sequence_number += tcp_segment_size;
        let ipv4_header_slice = Ipv4HeaderSlice::from_slice(&ipv4_header_buf).unwrap();
        let tcp_header_slice = TcpHeaderSlice::from_slice(&tcp_header_buf).unwrap();

        pcap_tcp_assembler.handle_segment(
            None,
            &ipv4_header_slice,
            &tcp_header_slice,
            &tcp_payload,
            &mut |consumable_tcp_payload, _connection_id, _tcp_connection, trace| try_consume_tcp_payload(consumable_tcp_payload, trace),
            &mut |_connection_id, tcp_connection, lost_bytes, trace| {
                if trace.is_some() {
                    println!("{} test - capture packet loss {} bytes {:?}", trace.unwrap(), lost_bytes, tcp_connection,);
                }
            },
        )
    }

    assert_eq!(next_message, application_messages.len());

    pcap_tcp_assembler.consume_all_buffers(
        &mut |consumable_tcp_payload, _connection_id, tcp_connection, trace| {
            println!(
                "{} test - receive_buffer is not empty {} bytes {:?}",
                trace.unwrap(),
                consumable_tcp_payload.len(),
                tcp_connection,
            );
            assert_eq!(consumable_tcp_payload.len(), 0);
            0
        },
        &mut |_connection_id, tcp_connection, lost_bytes, trace| {
            if trace.is_some() {
                println!("{} test - capture packet loss {} bytes {:?}", trace.unwrap(), lost_bytes, tcp_connection,);
            }
        },
    );
}

#[test]
fn test_messages_cross_segments() {
    // for message_size in 1..5000 {
    //     messages_cross_segments(message_size);
    // }
    [1, 2, 10, 13, 100, 200, 500, 1459, 1460, 1461, 3000, 5000].map(|message_size| {
        messages_cross_segments(message_size);
    });
}
#[test]
fn test_logging_channel() {
    let mut rng = rand::thread_rng();
    let tcp_payload: [u8; 10] = core::array::from_fn(|_| rng.gen::<u8>());
    let mut sequence_number = 1;
    let (ipv4_header_buf, tcp_header_buf) = generate_headers_buffers(sequence_number, &tcp_payload);
    let ipv4_header_slice = Ipv4HeaderSlice::from_slice(&ipv4_header_buf).unwrap();
    let tcp_header_slice = TcpHeaderSlice::from_slice(&tcp_header_buf).unwrap();

    let mut pcap_tcp_assembler = PcapTcpAssembler::new(RECEIVE_BUFFER_SIZE, TCP_ASSEMBLER_SIZE, Some(&[]));
    let mut consumed_size = 0;
    // Some packet on logging_channel 1
    pcap_tcp_assembler.handle_segment(
        Some(1),
        &ipv4_header_slice,
        &tcp_header_slice,
        &tcp_payload,
        &mut |consumable_tcp_payload, _connection_id, _tcp_connection, _trace| {
            assert_eq!(consumable_tcp_payload, tcp_payload);
            consumed_size += tcp_payload.len();

            tcp_payload.len() as u32
        },
        &mut |_connection_id, _tcp_connection, _lost_bytes, _trace| {
            panic!("Must not be called");
        },
    );
    // Duplicate packet on logging_channel 2
    pcap_tcp_assembler.handle_segment(
        Some(2),
        &ipv4_header_slice,
        &tcp_header_slice,
        &tcp_payload,
        &mut |_consumable_tcp_payload, _connection_id, _tcp_connection, _trace| {
            panic!("Must not be called");
        },
        &mut |_connection_id, tcp_connection, lost_bytes, trace| {
            println!("{} Test: capture packet loss {} bytes {:?}", trace.unwrap(), lost_bytes, tcp_connection,);
            panic!("Test: Must not be called");
        },
    );
    // Next packet on logging_channel 1
    sequence_number += tcp_payload.len() as u32;
    let (ipv4_header_buf, tcp_header_buf) = generate_headers_buffers(sequence_number, &tcp_payload);
    let ipv4_header_slice = Ipv4HeaderSlice::from_slice(&ipv4_header_buf).unwrap();
    let tcp_header_slice = TcpHeaderSlice::from_slice(&tcp_header_buf).unwrap();
    pcap_tcp_assembler.handle_segment(
        Some(1),
        &ipv4_header_slice,
        &tcp_header_slice,
        &tcp_payload,
        &mut |consumable_tcp_payload, _connection_id, _tcp_connection, _trace| {
            assert_eq!(consumable_tcp_payload, tcp_payload);
            consumed_size += tcp_payload.len();

            tcp_payload.len() as u32
        },
        &mut |_connection_id, tcp_connection, lost_bytes, trace| {
            println!("{} Test: capture packet loss {} bytes {:?}", trace.unwrap(), lost_bytes, tcp_connection,);
            panic!("Test: Must not be called");
        },
    );
    // Duplicate next packet on logging_channel 2
    pcap_tcp_assembler.handle_segment(
        Some(2),
        &ipv4_header_slice,
        &tcp_header_slice,
        &tcp_payload,
        &mut |_consumable_tcp_payload, _connection_id, _tcp_connection, _trace| {
            panic!("Must not be called");
        },
        &mut |_connection_id, tcp_connection, lost_bytes, trace| {
            println!("{} Test: capture packet loss {} bytes {:?}", trace.unwrap(), lost_bytes, tcp_connection,);
            panic!("Test: Must not be called");
        },
    );

    assert_eq!(consumed_size, tcp_payload.len() * 2);

    pcap_tcp_assembler.consume_all_buffers(
        &mut |consumable_tcp_payload, _connection_id, tcp_connection, trace| {
            println!(
                "{} Test: receive_buffer is not empty {} bytes {:?}",
                trace.unwrap(),
                consumable_tcp_payload.len(),
                tcp_connection,
            );
            panic!("Must not be called");
        },
        &mut |_connection_id, tcp_connection, lost_bytes, trace| {
            println!("{} Test: capture packet loss {} bytes {:?}", trace.unwrap(), lost_bytes, tcp_connection,);
            panic!("Test: Must not be called");
        },
    );
}
#[test]
fn test_sequence_number_rotated_all_consumed() {
    let mut rng = rand::thread_rng();

    let mut pcap_tcp_assembler = PcapTcpAssembler::new(RECEIVE_BUFFER_SIZE, TCP_ASSEMBLER_SIZE, Some(&[]));
    let mut consumed_size = 0;

    // Segment1 is close to the end of MAX_SEQUENCE_NUMBER
    let tcp_payload: [u8; 10] = core::array::from_fn(|_| rng.gen::<u8>());
    let sequence_number = pcap_tcp_assembler::MAX_SEQUENCE_NUMBER - tcp_payload.len() as u32 - tcp_payload.len() as u32 / 2;
    let (ipv4_header_buf, tcp_header_buf) = generate_headers_buffers(sequence_number, &tcp_payload);
    let ipv4_header_slice = Ipv4HeaderSlice::from_slice(&ipv4_header_buf).unwrap();
    let tcp_header_slice = TcpHeaderSlice::from_slice(&tcp_header_buf).unwrap();
    pcap_tcp_assembler.handle_segment(
        None,
        &ipv4_header_slice,
        &tcp_header_slice,
        &tcp_payload,
        &mut |consumable_tcp_payload, _connection_id, _tcp_connection, _trace| {
            assert_eq!(consumable_tcp_payload, tcp_payload);
            consumed_size += tcp_payload.len();

            tcp_payload.len() as u32
        },
        &mut |_connection_id, _tcp_connection, _lost_bytes, _trace| {
            panic!("Must not be called");
        },
    );

    // Segment2 is close to the end of MAX_SEQUENCE_NUMBER
    let tcp_payload: [u8; 10] = core::array::from_fn(|_| rng.gen::<u8>());
    let sequence_number = pcap_tcp_assembler::MAX_SEQUENCE_NUMBER - tcp_payload.len() as u32 / 2;
    let (ipv4_header_buf, tcp_header_buf) = generate_headers_buffers(sequence_number, &tcp_payload);
    let ipv4_header_slice = Ipv4HeaderSlice::from_slice(&ipv4_header_buf).unwrap();
    let tcp_header_slice = TcpHeaderSlice::from_slice(&tcp_header_buf).unwrap();
    pcap_tcp_assembler.handle_segment(
        None,
        &ipv4_header_slice,
        &tcp_header_slice,
        &tcp_payload,
        &mut |consumable_tcp_payload, _connection_id, _tcp_connection, _trace| {
            assert_eq!(consumable_tcp_payload, tcp_payload);
            consumed_size += tcp_payload.len();

            tcp_payload.len() as u32
        },
        &mut |_connection_id, _tcp_connection, _lost_bytes, _trace| {
            panic!("Must not be called");
        },
    );

    // Segment with rotated sequence number
    let tcp_payload: [u8; 10] = core::array::from_fn(|_| rng.gen::<u8>());
    let sequence_number = tcp_payload.len() as u32 / 2;
    let (ipv4_header_buf, tcp_header_buf) = generate_headers_buffers(sequence_number, &tcp_payload);
    let ipv4_header_slice = Ipv4HeaderSlice::from_slice(&ipv4_header_buf).unwrap();
    let tcp_header_slice = TcpHeaderSlice::from_slice(&tcp_header_buf).unwrap();
    pcap_tcp_assembler.handle_segment(
        None,
        &ipv4_header_slice,
        &tcp_header_slice,
        &tcp_payload,
        &mut |consumable_tcp_payload, _connection_id, _tcp_connection, _trace| {
            assert_eq!(consumable_tcp_payload, tcp_payload);
            consumed_size += tcp_payload.len();

            tcp_payload.len() as u32
        },
        &mut |_connection_id, tcp_connection, lost_bytes, trace| {
            println!("{} Test: capture packet loss {} bytes {:?}", trace.unwrap(), lost_bytes, tcp_connection,);
            panic!("Test: Must not be called");
        },
    );

    assert_eq!(consumed_size, tcp_payload.len() * 3);

    pcap_tcp_assembler.consume_all_buffers(
        &mut |consumable_tcp_payload, _connection_id, tcp_connection, trace| {
            println!(
                "{} Test: receive_buffer is not empty {} bytes {:?}",
                trace.unwrap(),
                consumable_tcp_payload.len(),
                tcp_connection,
            );
            panic!("Must not be called");
        },
        &mut |_connection_id, tcp_connection, lost_bytes, trace| {
            println!("{} Test: capture packet loss {} bytes {:?}", trace.unwrap(), lost_bytes, tcp_connection,);
            panic!("Test: Must not be called");
        },
    );
}
#[test]
fn test_sequence_number_rotated_delayed_consume() {
    let mut rng = rand::thread_rng();

    let mut pcap_tcp_assembler = PcapTcpAssembler::new(RECEIVE_BUFFER_SIZE, TCP_ASSEMBLER_SIZE, Some(&[]));
    let mut consumed_size = 0;

    // Segment1 is close to the end of MAX_SEQUENCE_NUMBER
    let tcp_payload1: [u8; 10] = core::array::from_fn(|_| rng.gen::<u8>());
    let sequence_number = pcap_tcp_assembler::MAX_SEQUENCE_NUMBER - tcp_payload1.len() as u32 - tcp_payload1.len() as u32 / 2;
    let (ipv4_header_buf, tcp_header_buf) = generate_headers_buffers(sequence_number, &tcp_payload1);
    let ipv4_header_slice = Ipv4HeaderSlice::from_slice(&ipv4_header_buf).unwrap();
    let tcp_header_slice = TcpHeaderSlice::from_slice(&tcp_header_buf).unwrap();
    let mut callback_called = false;
    pcap_tcp_assembler.handle_segment(
        None,
        &ipv4_header_slice,
        &tcp_header_slice,
        &tcp_payload1,
        &mut |consumable_tcp_payload, _connection_id, _tcp_connection, _trace| {
            assert_eq!(consumable_tcp_payload, tcp_payload1);
            callback_called = true;

            0
        },
        &mut |_connection_id, _tcp_connection, _lost_bytes, _trace| {
            panic!("Must not be called");
        },
    );
    assert_eq!(callback_called, true);
    callback_called = false;

    // Segment2 is close to the end of MAX_SEQUENCE_NUMBER
    let tcp_payload2: [u8; 10] = core::array::from_fn(|_| rng.gen::<u8>());
    let sequence_number = pcap_tcp_assembler::MAX_SEQUENCE_NUMBER - tcp_payload2.len() as u32 / 2;
    let (ipv4_header_buf, tcp_header_buf) = generate_headers_buffers(sequence_number, &tcp_payload2);
    let ipv4_header_slice = Ipv4HeaderSlice::from_slice(&ipv4_header_buf).unwrap();
    let tcp_header_slice = TcpHeaderSlice::from_slice(&tcp_header_buf).unwrap();
    pcap_tcp_assembler.handle_segment(
        None,
        &ipv4_header_slice,
        &tcp_header_slice,
        &tcp_payload2,
        &mut |consumable_tcp_payload, _connection_id, _tcp_connection, _trace| {
            assert_eq!(consumable_tcp_payload[..10], tcp_payload1);
            assert_eq!(consumable_tcp_payload[10..], tcp_payload2);
            callback_called = true;

            0
        },
        &mut |_connection_id, _tcp_connection, _lost_bytes, _trace| {
            panic!("Must not be called");
        },
    );

    assert_eq!(callback_called, true);

    // Segment with rotated sequence number
    let tcp_payload3: [u8; 10] = core::array::from_fn(|_| rng.gen::<u8>());
    let sequence_number = tcp_payload3.len() as u32 / 2;
    let (ipv4_header_buf, tcp_header_buf) = generate_headers_buffers(sequence_number, &tcp_payload3);
    let ipv4_header_slice = Ipv4HeaderSlice::from_slice(&ipv4_header_buf).unwrap();
    let tcp_header_slice = TcpHeaderSlice::from_slice(&tcp_header_buf).unwrap();
    pcap_tcp_assembler.handle_segment(
        None,
        &ipv4_header_slice,
        &tcp_header_slice,
        &tcp_payload3,
        &mut |consumable_tcp_payload, _connection_id, _tcp_connection, _trace| {
            assert_eq!(consumable_tcp_payload[..10], tcp_payload1);
            assert_eq!(consumable_tcp_payload[10..20], tcp_payload2);
            assert_eq!(consumable_tcp_payload[20..], tcp_payload3);
            consumed_size = 30;

            30
        },
        &mut |_connection_id, tcp_connection, lost_bytes, trace| {
            println!("{} Test: capture packet loss {} bytes {:?}", trace.unwrap(), lost_bytes, tcp_connection,);
            panic!("Test: Must not be called");
        },
    );

    assert_eq!(consumed_size, 30);

    pcap_tcp_assembler.consume_all_buffers(
        &mut |consumable_tcp_payload, _connection_id, tcp_connection, trace| {
            println!(
                "{} Test: receive_buffer is not empty {} bytes {:?}",
                trace.unwrap(),
                consumable_tcp_payload.len(),
                tcp_connection,
            );
            panic!("Must not be called");
        },
        &mut |_connection_id, tcp_connection, lost_bytes, trace| {
            println!("{} Test: capture packet loss {} bytes {:?}", trace.unwrap(), lost_bytes, tcp_connection,);
            panic!("Test: Must not be called");
        },
    );
}
#[test]
fn test_sequence_number_within_old_duplicate_threshold() {
    let mut rng = rand::thread_rng();

    let mut pcap_tcp_assembler = PcapTcpAssembler::new(RECEIVE_BUFFER_SIZE, TCP_ASSEMBLER_SIZE, Some(&[]));

    let tcp_payload1: [u8; 10] = core::array::from_fn(|_| rng.gen::<u8>());
    let sequence_number = pcap_tcp_assembler::SEQUENCE_NUMBER_OLD_DUPLICATE_THRESHOLD;
    let (ipv4_header_buf, tcp_header_buf) = generate_headers_buffers(sequence_number, &tcp_payload1);
    let ipv4_header_slice = Ipv4HeaderSlice::from_slice(&ipv4_header_buf).unwrap();
    let tcp_header_slice = TcpHeaderSlice::from_slice(&tcp_header_buf).unwrap();
    let mut callback_called = false;
    pcap_tcp_assembler.handle_segment(
        None,
        &ipv4_header_slice,
        &tcp_header_slice,
        &tcp_payload1,
        &mut |consumable_tcp_payload, _connection_id, _tcp_connection, _trace| {
            assert_eq!(consumable_tcp_payload, tcp_payload1);
            callback_called = true;

            0
        },
        &mut |_connection_id, _tcp_connection, _lost_bytes, _trace| {
            panic!("Must not be called");
        },
    );
    assert_eq!(callback_called, true);
    callback_called = false;

    let tcp_payload2: [u8; 10] = core::array::from_fn(|_| rng.gen::<u8>());
    let sequence_number = sequence_number - 1;
    let (_, tcp_header_buf) = generate_headers_buffers(sequence_number, &tcp_payload2);
    let tcp_header_slice = TcpHeaderSlice::from_slice(&tcp_header_buf).unwrap();
    pcap_tcp_assembler.handle_segment(
        None,
        &ipv4_header_slice,
        &tcp_header_slice,
        &tcp_payload2,
        &mut |_consumable_tcp_payload, _connection_id, _tcp_connection, _trace| {
            callback_called = true;

            tcp_payload1.len() as u32
        },
        &mut |_connection_id, _tcp_connection, _lost_bytes, _trace| {
            panic!("Must not be called");
        },
    );

    assert_eq!(callback_called, false);

    pcap_tcp_assembler.consume_all_buffers(
        &mut |consumable_tcp_payload, _connection_id, _tcp_connection, _trace| {
            assert_eq!(consumable_tcp_payload, tcp_payload1);

            tcp_payload1.len() as u32
        },
        &mut |_connection_id, tcp_connection, lost_bytes, trace| {
            println!("{} Test: capture packet loss {} bytes {:?}", trace.unwrap(), lost_bytes, tcp_connection,);
            panic!("Test: Must not be called");
        },
    );
}
#[test]
fn test_sequence_number_outside_of_old_duplicate_threshold() {
    let mut rng = rand::thread_rng();

    let mut pcap_tcp_assembler = PcapTcpAssembler::new(RECEIVE_BUFFER_SIZE, TCP_ASSEMBLER_SIZE, Some(&[]));

    let tcp_payload1: [u8; 10] = core::array::from_fn(|_| rng.gen::<u8>());
    let sequence_number = pcap_tcp_assembler::SEQUENCE_NUMBER_OLD_DUPLICATE_THRESHOLD + 100;
    let (ipv4_header_buf, tcp_header_buf) = generate_headers_buffers(sequence_number, &tcp_payload1);
    let ipv4_header_slice = Ipv4HeaderSlice::from_slice(&ipv4_header_buf).unwrap();
    let tcp_header_slice = TcpHeaderSlice::from_slice(&tcp_header_buf).unwrap();
    let mut callback_called = false;
    pcap_tcp_assembler.handle_segment(
        None,
        &ipv4_header_slice,
        &tcp_header_slice,
        &tcp_payload1,
        &mut |consumable_tcp_payload, _connection_id, _tcp_connection, _trace| {
            assert_eq!(consumable_tcp_payload, tcp_payload1);
            callback_called = true;

            0
        },
        &mut |_connection_id, _tcp_connection, _lost_bytes, _trace| {
            panic!("Must not be called");
        },
    );
    assert_eq!(callback_called, true);
    callback_called = false;

    let tcp_payload2: [u8; 10] = core::array::from_fn(|_| rng.gen::<u8>());
    let sequence_number = sequence_number - pcap_tcp_assembler::SEQUENCE_NUMBER_OLD_DUPLICATE_THRESHOLD - 1;
    let (_, tcp_header_buf) = generate_headers_buffers(sequence_number, &tcp_payload2);
    let tcp_header_slice = TcpHeaderSlice::from_slice(&tcp_header_buf).unwrap();
    pcap_tcp_assembler.handle_segment(
        None,
        &ipv4_header_slice,
        &tcp_header_slice,
        &tcp_payload2,
        &mut |consumable_tcp_payload, _connection_id, _tcp_connection, _trace| {
            if !callback_called {
                assert_eq!(consumable_tcp_payload, tcp_payload1);
            } else {
                assert_eq!(consumable_tcp_payload, tcp_payload2);
            }
            callback_called = true;

            tcp_payload1.len() as u32
        },
        &mut |_connection_id, _tcp_connection, _lost_bytes, _trace| {
            panic!("Must not be called");
        },
    );

    assert_eq!(callback_called, true);

    pcap_tcp_assembler.consume_all_buffers(
        &mut |consumable_tcp_payload, _connection_id, tcp_connection, trace| {
            println!(
                "{} Test: receive_buffer is not empty {} bytes {:?}",
                trace.unwrap(),
                consumable_tcp_payload.len(),
                tcp_connection,
            );
            panic!("Must not be called");
        },
        &mut |_connection_id, tcp_connection, lost_bytes, trace| {
            println!("{} Test: capture packet loss {} bytes {:?}", trace.unwrap(), lost_bytes, tcp_connection,);
            panic!("Test: Must not be called");
        },
    );
}
#[test]
fn test_sequence_number_outside_of_receive_buffer() {
    let mut rng = rand::thread_rng();

    let mut pcap_tcp_assembler = PcapTcpAssembler::new(RECEIVE_BUFFER_SIZE, TCP_ASSEMBLER_SIZE, Some(&[]));

    let tcp_payload1: [u8; 10] = core::array::from_fn(|_| rng.gen::<u8>());
    let sequence_number = 500;
    let (ipv4_header_buf, tcp_header_buf) = generate_headers_buffers(sequence_number, &tcp_payload1);
    let ipv4_header_slice = Ipv4HeaderSlice::from_slice(&ipv4_header_buf).unwrap();
    let tcp_header_slice = TcpHeaderSlice::from_slice(&tcp_header_buf).unwrap();
    let mut callback_called = false;
    pcap_tcp_assembler.handle_segment(
        None,
        &ipv4_header_slice,
        &tcp_header_slice,
        &tcp_payload1,
        &mut |consumable_tcp_payload, _connection_id, _tcp_connection, _trace| {
            assert_eq!(consumable_tcp_payload, tcp_payload1);
            callback_called = true;

            0
        },
        &mut |_connection_id, _tcp_connection, _lost_bytes, _trace| {
            panic!("Must not be called");
        },
    );
    assert_eq!(callback_called, true);
    callback_called = false;

    let tcp_payload2: [u8; 10] = core::array::from_fn(|_| rng.gen::<u8>());
    let sequence_number = sequence_number + RECEIVE_BUFFER_SIZE as u32 + 1;
    let (_, tcp_header_buf) = generate_headers_buffers(sequence_number, &tcp_payload2);
    let tcp_header_slice = TcpHeaderSlice::from_slice(&tcp_header_buf).unwrap();
    pcap_tcp_assembler.handle_segment(
        None,
        &ipv4_header_slice,
        &tcp_header_slice,
        &tcp_payload2,
        &mut |consumable_tcp_payload, _connection_id, _tcp_connection, _trace| {
            if !callback_called {
                assert_eq!(consumable_tcp_payload, tcp_payload1);
            } else {
                assert_eq!(consumable_tcp_payload, tcp_payload2);
            }
            callback_called = true;

            tcp_payload1.len() as u32
        },
        &mut |_connection_id, _tcp_connection, _lost_bytes, _trace| {
            panic!("Must not be called");
        },
    );

    assert_eq!(callback_called, true);

    pcap_tcp_assembler.consume_all_buffers(
        &mut |consumable_tcp_payload, _connection_id, tcp_connection, trace| {
            println!(
                "{} Test: receive_buffer is not empty {} bytes {:?}",
                trace.unwrap(),
                consumable_tcp_payload.len(),
                tcp_connection,
            );
            panic!("Must not be called");
        },
        &mut |_connection_id, tcp_connection, lost_bytes, trace| {
            println!("{} Test: capture packet loss {} bytes {:?}", trace.unwrap(), lost_bytes, tcp_connection,);
            panic!("Test: Must not be called");
        },
    );
}
#[test]
fn test_flags_rst() {
    let mut rng = rand::thread_rng();

    let mut pcap_tcp_assembler = PcapTcpAssembler::new(RECEIVE_BUFFER_SIZE, TCP_ASSEMBLER_SIZE, Some(&[]));

    let tcp_payload1: [u8; 10] = core::array::from_fn(|_| rng.gen::<u8>());
    let mut tcp_header_vec1 = BufWriter::new(Vec::new());
    let mut tcp_header1 = TcpHeader::new(1000, 80, 100, 65535);
    tcp_header1.write(&mut tcp_header_vec1).unwrap();
    let mut tcp_header_buf1 = tcp_header_vec1.into_inner().unwrap();
    tcp_header_buf1.extend_from_slice(&tcp_payload1);
    let tcp_header_slice1 = TcpHeaderSlice::from_slice(&tcp_header_buf1).unwrap();

    let mut ipv4_header_buf1 = BufWriter::new(Vec::new());
    let ipv4_header1 = Ipv4Header::new(tcp_header_buf1.len() as u16, 64, IpNumber::Tcp as u8, [192, 168, 1, 1], [192, 168, 1, 2]);
    ipv4_header1.write(&mut ipv4_header_buf1).unwrap();
    let ipv4_header_buf1 = ipv4_header_buf1.into_inner().unwrap();
    let ipv4_header_slice1 = Ipv4HeaderSlice::from_slice(&ipv4_header_buf1).unwrap();

    let mut callback_called = false;
    pcap_tcp_assembler.handle_segment(
        None,
        &ipv4_header_slice1,
        &tcp_header_slice1,
        &tcp_payload1,
        &mut |consumable_tcp_payload, _connection_id, _tcp_connection, _trace| {
            assert_eq!(consumable_tcp_payload, tcp_payload1);
            callback_called = true;

            0
        },
        &mut |_connection_id, _tcp_connection, _lost_bytes, _trace| {
            panic!("Must not be called");
        },
    );
    assert_eq!(callback_called, true);
    callback_called = false;

    let tcp_payload2: [u8; 10] = core::array::from_fn(|_| rng.gen::<u8>());
    let mut tcp_header_vec2 = BufWriter::new(Vec::new());
    let tcp_header2 = TcpHeader::new(80, 1000, 100, 65535);
    tcp_header2.write(&mut tcp_header_vec2).unwrap();
    let mut tcp_header_buf2 = tcp_header_vec2.into_inner().unwrap();
    tcp_header_buf2.extend_from_slice(&tcp_payload2);
    let tcp_header_slice2 = TcpHeaderSlice::from_slice(&tcp_header_buf2).unwrap();

    let mut ipv4_header_buf2 = BufWriter::new(Vec::new());
    let ipv4_header2 = Ipv4Header::new(tcp_header_buf2.len() as u16, 64, IpNumber::Tcp as u8, [192, 168, 1, 2], [192, 168, 1, 1]);
    ipv4_header2.write(&mut ipv4_header_buf2).unwrap();
    let ipv4_header_buf2 = ipv4_header_buf2.into_inner().unwrap();
    let ipv4_header_slice2 = Ipv4HeaderSlice::from_slice(&ipv4_header_buf2).unwrap();

    pcap_tcp_assembler.handle_segment(
        None,
        &ipv4_header_slice2,
        &tcp_header_slice2,
        &tcp_payload2,
        &mut |consumable_tcp_payload, _connection_id, _tcp_connection, _trace| {
            assert_eq!(consumable_tcp_payload, tcp_payload2);
            callback_called = true;

            0
        },
        &mut |_connection_id, _tcp_connection, _lost_bytes, _trace| {
            panic!("Must not be called");
        },
    );
    assert_eq!(callback_called, true);
    callback_called = false;

    // Test
    tcp_header1.rst = true;

    let mut tcp_header_vec1 = BufWriter::new(Vec::new());
    tcp_header1.write(&mut tcp_header_vec1).unwrap();
    let mut tcp_header_buf1 = tcp_header_vec1.into_inner().unwrap();
    tcp_header_buf1.extend_from_slice(&tcp_payload1);
    let tcp_header_slice1 = TcpHeaderSlice::from_slice(&tcp_header_buf1).unwrap();

    pcap_tcp_assembler.handle_segment(
        None,
        &ipv4_header_slice1,
        &tcp_header_slice1,
        &tcp_payload1,
        &mut |consumable_tcp_payload, _connection_id, tcp_connection, _trace| {
            if !callback_called {
                assert_eq!(*tcp_connection, TcpConnection {
                    source_ipv4_address: [192, 168, 1, 1].into(),
                    source_port: 1000,
                    destination_ipv4_address: [192, 168, 1, 2].into(),
                    destination_port: 80,
                });
                assert_eq!(consumable_tcp_payload, tcp_payload1);
            } else {
                assert_eq!(*tcp_connection, TcpConnection {
                    source_ipv4_address: [192, 168, 1, 2].into(),
                    source_port: 80,
                    destination_ipv4_address: [192, 168, 1, 1].into(),
                    destination_port: 1000,
                });
                assert_eq!(consumable_tcp_payload, tcp_payload2);
            }
            callback_called = true;

            tcp_payload1.len() as u32
        },
        &mut |_connection_id, _tcp_connection, _lost_bytes, _trace| {
            panic!("Must not be called");
        },
    );
    assert_eq!(callback_called, true);

    pcap_tcp_assembler.consume_all_buffers(
        &mut |consumable_tcp_payload, _connection_id, tcp_connection, trace| {
            println!(
                "{} Test: receive_buffer is not empty {} bytes {:?}",
                trace.unwrap(),
                consumable_tcp_payload.len(),
                tcp_connection,
            );
            panic!("Must not be called");
        },
        &mut |_connection_id, tcp_connection, lost_bytes, trace| {
            println!("{} Test: capture packet loss {} bytes {:?}", trace.unwrap(), lost_bytes, tcp_connection,);
            panic!("Test: Must not be called");
        },
    );
}
#[test]
fn test_flags_syn() {
    let mut rng = rand::thread_rng();

    let mut pcap_tcp_assembler = PcapTcpAssembler::new(RECEIVE_BUFFER_SIZE, TCP_ASSEMBLER_SIZE, Some(&[]));

    let tcp_payload1: [u8; 10] = core::array::from_fn(|_| rng.gen::<u8>());
    let mut tcp_header_vec1 = BufWriter::new(Vec::new());
    let mut tcp_header1 = TcpHeader::new(1000, 80, 100, 65535);
    tcp_header1.write(&mut tcp_header_vec1).unwrap();
    let mut tcp_header_buf1 = tcp_header_vec1.into_inner().unwrap();
    tcp_header_buf1.extend_from_slice(&tcp_payload1);
    let tcp_header_slice1 = TcpHeaderSlice::from_slice(&tcp_header_buf1).unwrap();

    let mut ipv4_header_buf1 = BufWriter::new(Vec::new());
    let ipv4_header1 = Ipv4Header::new(tcp_header_buf1.len() as u16, 64, IpNumber::Tcp as u8, [192, 168, 1, 1], [192, 168, 1, 2]);
    ipv4_header1.write(&mut ipv4_header_buf1).unwrap();
    let ipv4_header_buf1 = ipv4_header_buf1.into_inner().unwrap();
    let ipv4_header_slice1 = Ipv4HeaderSlice::from_slice(&ipv4_header_buf1).unwrap();

    let mut callback_called = false;
    pcap_tcp_assembler.handle_segment(
        None,
        &ipv4_header_slice1,
        &tcp_header_slice1,
        &tcp_payload1,
        &mut |consumable_tcp_payload, _connection_id, _tcp_connection, _trace| {
            assert_eq!(consumable_tcp_payload, tcp_payload1);
            callback_called = true;

            0
        },
        &mut |_connection_id, _tcp_connection, _lost_bytes, _trace| {
            panic!("Must not be called");
        },
    );
    assert_eq!(callback_called, true);
    callback_called = false;

    let tcp_payload2: [u8; 10] = core::array::from_fn(|_| rng.gen::<u8>());
    let mut tcp_header_vec2 = BufWriter::new(Vec::new());
    let tcp_header2 = TcpHeader::new(80, 1000, 100, 65535);
    tcp_header2.write(&mut tcp_header_vec2).unwrap();
    let mut tcp_header_buf2 = tcp_header_vec2.into_inner().unwrap();
    tcp_header_buf2.extend_from_slice(&tcp_payload2);
    let tcp_header_slice2 = TcpHeaderSlice::from_slice(&tcp_header_buf2).unwrap();

    let mut ipv4_header_buf2 = BufWriter::new(Vec::new());
    let ipv4_header2 = Ipv4Header::new(tcp_header_buf2.len() as u16, 64, IpNumber::Tcp as u8, [192, 168, 1, 2], [192, 168, 1, 1]);
    ipv4_header2.write(&mut ipv4_header_buf2).unwrap();
    let ipv4_header_buf2 = ipv4_header_buf2.into_inner().unwrap();
    let ipv4_header_slice2 = Ipv4HeaderSlice::from_slice(&ipv4_header_buf2).unwrap();

    pcap_tcp_assembler.handle_segment(
        None,
        &ipv4_header_slice2,
        &tcp_header_slice2,
        &tcp_payload2,
        &mut |consumable_tcp_payload, _connection_id, _tcp_connection, _trace| {
            assert_eq!(consumable_tcp_payload, tcp_payload2);
            callback_called = true;

            0
        },
        &mut |_connection_id, _tcp_connection, _lost_bytes, _trace| {
            panic!("Must not be called");
        },
    );
    assert_eq!(callback_called, true);
    callback_called = false;

    // Test
    tcp_header1.syn = true;

    let mut tcp_header_vec1 = BufWriter::new(Vec::new());
    tcp_header1.write(&mut tcp_header_vec1).unwrap();
    let mut tcp_header_buf1 = tcp_header_vec1.into_inner().unwrap();
    tcp_header_buf1.extend_from_slice(&tcp_payload1);
    let tcp_header_slice1 = TcpHeaderSlice::from_slice(&tcp_header_buf1).unwrap();

    pcap_tcp_assembler.handle_segment(
        None,
        &ipv4_header_slice1,
        &tcp_header_slice1,
        &tcp_payload1,
        &mut |consumable_tcp_payload, _connection_id, tcp_connection, _trace| {
            if !callback_called {
                assert_eq!(*tcp_connection, TcpConnection {
                    source_ipv4_address: [192, 168, 1, 1].into(),
                    source_port: 1000,
                    destination_ipv4_address: [192, 168, 1, 2].into(),
                    destination_port: 80,
                });
                assert_eq!(consumable_tcp_payload, tcp_payload1);
            } else {
                assert_eq!(*tcp_connection, TcpConnection {
                    source_ipv4_address: [192, 168, 1, 2].into(),
                    source_port: 80,
                    destination_ipv4_address: [192, 168, 1, 1].into(),
                    destination_port: 1000,
                });
                assert_eq!(consumable_tcp_payload, tcp_payload2);
            }
            callback_called = true;

            tcp_payload1.len() as u32
        },
        &mut |_connection_id, _tcp_connection, _lost_bytes, _trace| {
            panic!("Must not be called");
        },
    );
    assert_eq!(callback_called, true);

    pcap_tcp_assembler.consume_all_buffers(
        &mut |consumable_tcp_payload, _connection_id, tcp_connection, trace| {
            println!(
                "{} Test: receive_buffer is not empty {} bytes {:?}",
                trace.unwrap(),
                consumable_tcp_payload.len(),
                tcp_connection,
            );
            panic!("Must not be called");
        },
        &mut |_connection_id, tcp_connection, lost_bytes, trace| {
            println!("{} Test: capture packet loss {} bytes {:?}", trace.unwrap(), lost_bytes, tcp_connection,);
            panic!("Test: Must not be called");
        },
    );
}
#[test]
fn test_flags_fin() {
    let mut rng = rand::thread_rng();

    let mut pcap_tcp_assembler = PcapTcpAssembler::new(RECEIVE_BUFFER_SIZE, TCP_ASSEMBLER_SIZE, Some(&[]));

    let tcp_payload1: [u8; 10] = core::array::from_fn(|_| rng.gen::<u8>());
    let mut tcp_header_vec1 = BufWriter::new(Vec::new());
    let tcp_header1 = TcpHeader::new(1000, 80, 100, 65535);
    tcp_header1.write(&mut tcp_header_vec1).unwrap();
    let mut tcp_header_buf1 = tcp_header_vec1.into_inner().unwrap();
    tcp_header_buf1.extend_from_slice(&tcp_payload1);
    let tcp_header_slice1 = TcpHeaderSlice::from_slice(&tcp_header_buf1).unwrap();

    let mut ipv4_header_buf1 = BufWriter::new(Vec::new());
    let ipv4_header1 = Ipv4Header::new(tcp_header_buf1.len() as u16, 64, IpNumber::Tcp as u8, [192, 168, 1, 1], [192, 168, 1, 2]);
    ipv4_header1.write(&mut ipv4_header_buf1).unwrap();
    let ipv4_header_buf1 = ipv4_header_buf1.into_inner().unwrap();
    let ipv4_header_slice1 = Ipv4HeaderSlice::from_slice(&ipv4_header_buf1).unwrap();

    let mut callback_called = false;
    pcap_tcp_assembler.handle_segment(
        None,
        &ipv4_header_slice1,
        &tcp_header_slice1,
        &tcp_payload1,
        &mut |consumable_tcp_payload, _connection_id, _tcp_connection, _trace| {
            assert_eq!(consumable_tcp_payload, tcp_payload1);
            callback_called = true;

            0
        },
        &mut |_connection_id, _tcp_connection, _lost_bytes, _trace| {
            panic!("Must not be called");
        },
    );
    assert_eq!(callback_called, true);
    callback_called = false;

    let tcp_payload2: [u8; 10] = core::array::from_fn(|_| rng.gen::<u8>());
    let mut tcp_header_vec2 = BufWriter::new(Vec::new());
    let tcp_header2 = TcpHeader::new(80, 1000, 100, 65535);
    tcp_header2.write(&mut tcp_header_vec2).unwrap();
    let mut tcp_header_buf2 = tcp_header_vec2.into_inner().unwrap();
    tcp_header_buf2.extend_from_slice(&tcp_payload2);
    let tcp_header_slice2 = TcpHeaderSlice::from_slice(&tcp_header_buf2).unwrap();

    let mut ipv4_header_buf2 = BufWriter::new(Vec::new());
    let ipv4_header2 = Ipv4Header::new(tcp_header_buf2.len() as u16, 64, IpNumber::Tcp as u8, [192, 168, 1, 2], [192, 168, 1, 1]);
    ipv4_header2.write(&mut ipv4_header_buf2).unwrap();
    let ipv4_header_buf2 = ipv4_header_buf2.into_inner().unwrap();
    let ipv4_header_slice2 = Ipv4HeaderSlice::from_slice(&ipv4_header_buf2).unwrap();

    pcap_tcp_assembler.handle_segment(
        None,
        &ipv4_header_slice2,
        &tcp_header_slice2,
        &tcp_payload2,
        &mut |consumable_tcp_payload, _connection_id, _tcp_connection, _trace| {
            assert_eq!(consumable_tcp_payload, tcp_payload2);
            callback_called = true;

            0
        },
        &mut |_connection_id, _tcp_connection, _lost_bytes, _trace| {
            panic!("Must not be called");
        },
    );
    assert_eq!(callback_called, true);
    callback_called = false;

    // Test
    let mut tcp_header3 = TcpHeader::new(1000, 80, 0, 0);
    tcp_header3.fin = true;

    let mut tcp_header_vec3 = BufWriter::new(Vec::new());
    tcp_header3.write(&mut tcp_header_vec3).unwrap();
    let tcp_header_buf3 = tcp_header_vec3.into_inner().unwrap();
    let tcp_header_slice3 = TcpHeaderSlice::from_slice(&tcp_header_buf3).unwrap();

    pcap_tcp_assembler.handle_segment(
        None,
        &ipv4_header_slice1,
        &tcp_header_slice3,
        &[],
        &mut |consumable_tcp_payload, _connection_id, tcp_connection, _trace| {
            if !callback_called {
                assert_eq!(*tcp_connection, TcpConnection {
                    source_ipv4_address: [192, 168, 1, 1].into(),
                    source_port: 1000,
                    destination_ipv4_address: [192, 168, 1, 2].into(),
                    destination_port: 80,
                });
                assert_eq!(consumable_tcp_payload, tcp_payload1);
            } else {
                assert_eq!(*tcp_connection, TcpConnection {
                    source_ipv4_address: [192, 168, 1, 2].into(),
                    source_port: 80,
                    destination_ipv4_address: [192, 168, 1, 1].into(),
                    destination_port: 1000,
                });
                assert_eq!(consumable_tcp_payload, tcp_payload2);
            }
            callback_called = true;

            tcp_payload1.len() as u32
        },
        &mut |_connection_id, _tcp_connection, _lost_bytes, _trace| {
            panic!("Must not be called");
        },
    );
    assert_eq!(callback_called, true);

    pcap_tcp_assembler.consume_all_buffers(
        &mut |consumable_tcp_payload, _connection_id, tcp_connection, trace| {
            println!(
                "{} Test: receive_buffer is not empty {} bytes {:?}",
                trace.unwrap(),
                consumable_tcp_payload.len(),
                tcp_connection,
            );
            panic!("Must not be called");
        },
        &mut |_connection_id, tcp_connection, lost_bytes, trace| {
            println!("{} Test: capture packet loss {} bytes {:?}", trace.unwrap(), lost_bytes, tcp_connection,);
            panic!("Test: Must not be called");
        },
    );
}
// TODO: Add more tests
// - started in a middle of TCP stream some first bytes cannot be consumed
// - Leading hole
// - Middle hole
// - inform_packet loss