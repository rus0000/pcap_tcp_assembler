# PCAP TCP Assembler
- TCP segments re-assembly and application message detection optimized for PCAP processing.

# Use-case
- PCAP TCP Assembler is intended for **log analysis of message exchange**, when message loss could be tolerated during analysis.
- It also could be helpful for TCP payloads extraction like files transfer, and also for streaming protocols on top of TCP, which can tolerate packet loss. For such use-cases, it could be used together with Wireshark to manually extract payloads.

# Motivation
PCAP TCP Assembler solves two tasks, which must be solved, when consuming TCP byte-stream from PCAP:
- Packet loss on capture. **Recover and continue.**
- Message detection. **This greatly simplifies application logic.**

## Packet loss on capture
- Handle lost TCP segments. TCP protocol does not allow data loss, but capture tools do!
- Wireshark, tshark, tcpdump, nPCAP, hardware probes and loggers are dropping packets on capture. That means, TCP segment was received and acknowledged, but not in the PCAP.
- PCAP TCP Assembler allows TCP segment loss, when reading packets from PCAP. It will recover and continue.
- Regular "TCP segments re-assembler", which is used for communication, will not work in this case. TCP protocol does not allow segments loss. It will stuck in case of lost packet in PCAP.
- PCAP TCP Assembler will await for lost segments while iterating over packets in the PCAP file, then drop lost segment and try to recover.
- Application is notified of data loss with a callback to handle it on higher level protocols.

## Message detection
- PCAP TCP Assembler helps to detect the beginning of the higher level protocol message - called further "Application message". For example - HTTP.
- TCP stream could be captured not from beginning, but in the middle.
- TCP stream could have lost segments - capture loss.
- Message detection logic allows to scan through TCP stream by one byte and test for valid message header by application provided callback.
- PCAP TCP Assembler uses TCP receive buffer for this task, so Application does not need to implement this logic and does not need to allocate more buffers for this task.
- Application, which consumes TCP payload from PCAP, provides a callback to detect a beginning of application message in the TCP byte-stream.

# Description
- TCP connection - one direction of data flow: [source IP:port, destination IP:port].
- TCP session - two TCP connections.
- TCP stream - a byte-stream of TCP payload. 
    - One per TCP connection. 
    - TCP has no notion of message. TCP segment border does not indicate beginning or end of application message. Goal of PCAP TCP Assembler is to help application to deal with TCP stream.
- Use [etherparse](https://github.com/JulianSchmid/etherparse) base types.
- Use modified [smoltcp](https://github.com/smoltcp-rs/smoltcp) `storage::Assembler`.
- Support TCP retransmission, out-of-order segments reassembly.
- Support TCP segment loss by capture. Case, when packet was received and acknowledged on the wire, but not captured in the PCAP. 
- Use double VLAN tagging if it is present to avoid processing duplicate packets, captured multiple times on the path by probes. Automotive use-case.
- On data loss, inform application, try to recover and continue.
- Wait until lost TCP segments are received until receive buffer is full. The larger the receive buffer is, the longer assembler will await for missing TCP segments.
- Awaiting for missing TCP segments will delay payload consumption on this TCP connection. Since there are two TCP connections per TCP session, this could lead to desynchronization of messages inside one TCP session.
- High level protocol Request/Response message order between TCP connections is NOT guaranteed by PCAP TCP Assembler. Only bytes order within each TCP stream is guaranteed. 
- Application could enforce message order. 
    - Example: HTTP Request/Response exchange.
    - In this TCP session, 
        - TCP connection1 is sending **Requests** from IP address A to B
        - TCP connection2 is sending **Responses** from B to A.
    - Application consume Request1 message from TCP connection1.
    - Application should delay to consume next Request2 on TCP connection1. Application should wait until Response1 is received on TCP connection2. 
    - Application should handle a case, that  Response1 could be lost and never received. 
    - Application should reset message exchange and drop both: valid and received Request1 and lost Response1.
    - Then continue with next Request2/Response2.

# TCP re-assembly
- TCP re-assembly is needed to restore continuous byte-stream from TCP segments.
- Processing TCP from PCAP is similar to implementing a receiving part of TCP stack. 
- Difference is:
    - PCAP could have packet loss, which has happened during PCAP capture, not during TCP communication.
    - PCAP could be captured not from beginning of communication. For example, TCP SYN could be not captured.
    - TCP byte stream should recover in this case. Next consumable data should be found and further consumed by Application.
    - Application should detect a message beginning, which is not needed in live communication.
- TCP has no any message delimiters in protocol. Only Application could decide, where message starts and ends inside TCP byte-stream.
- PCAP TCP Assembler goal is a maximal consumption of useable TCP stream.

# Implementation
- [Implementation.md](Implementation.md)
- Per TCP connection use two pre-allocated buffers instead of RingBuffer.
- Regular TCP reception during live communication uses Receive Window + Window Scaling TCP option. Receive Window is not related to implementation of PCAP TCP Assembler. 
- Use for PCAP processing two relatively large receive buffers, not related to TCP Receive Window. Size of buffers determines how long to await lost TCP segment.
- Two buffers are used to rotate them and speed-up copying, when dropping leading hole.

# How to use
- Please see docs API details `cargo doc && target/doc/pcap_tcp_assembler/index.html`
- Instantiate single instance of `PcapTcpAssembler`, provide receive buffer size, amount of tracking holes in TCP byte-stream and tracing option
- Iterate PCAP packets. For each TCP packet call `handle_segment()`
    - Provide two callbacks 
        - `try_consume_tcp_payload()` to detect application message beginning and consume data 
        - `inform_packet_loss()` to handle data loss
- Call `consume_all_buffers()` to drain all buffers at the end of PCAP file, after last segment was assembled.

# Tracing
- `PcapTcpAssembler::new(trace_connections: Option<&'a [u32]>);` 
    - `trace_connections` - list of connection ids to trace into console. Empty slice - trace all. `None` - do not trace.

# Example - Extract HTTP
- [examples/extract_http.rs](examples/extract_http.rs)
- Use [rpcap](https://github.com/maltek/rpcap) crate for reading PCAP file.
- Use HTTP Parser [httparse](https://github.com/seanmonstar/httparse) crate.
- `cargo run --example extract_http .\examples\segmented_tcp2.pcap`
- Please see example result in [segmented_tcp2.txt](examples/segmented_tcp2.txt)
- Support HTTP/1.0, HTTP/1.1. 
- Do not support HTTP/2, HTTP/3(QUIC) protocols.
- Do not support HTTPS protocol, since it is wrapped in TLS and not visible in PCAP.
- Do not support compression.
- Do not support PCAPNG files. Please convert PCAPNG to PCAP with Wireshark.
- Example prints parsed HTTP conversation into console. HTTP content is truncated to 100chars, but HTTP content is fully loaded.

# How to run tests
```sh
~ cargo test
```

# How to run test coverage
https://github.com/xd009642/tarpaulin
```sh
~ cargo install cargo-tarpaulin
~ cargo tarpaulin --out Html --tests
```

# License
- Copyright (c) 2024 Ruslan Iusupov <https://github.com/rus0000>
- SPDX-License-Identifier: MIT
- smoltcp TCP Assembler part is 0BSD
- Copyright (c) 2016 whitequark@whitequark.org
- SPDX-License-Identifier: 0BSD
