# PCAP TCP assembler implementation details

# Terminology
- TCP connection - one direction of data flow: [source IP:port, destination IP:port].
- TCP session has two TCP connections.
- TCP stream - a byte-stream of TCP payload.
    - One per TCP connection.
    - TCP has no notion of message. TCP segment border does not indicate beginning or end of application message. Goal of PCAP TCP Assembler is to deal with TCP stream.
- Head - start of the receive buffer.
- Tail - end of the receive buffer.
- Hole - not yet received TCP segments in receive_buffer.
- Leading hole - not yet received segments at Head.
    - Logically present in both `tcp_assembler` and `receive_buffer`.
    - It could happen, that leading hole will never be filled, as buffer progresses over the TCP stream. If segment needed to fill the hole will be received too late, it will be dropped.
 - Hole in the middle.
    - could become a leading hole, as buffer progresses over the TCP stream.
    - could be filled later by retransmitted segment
- consume bytes - Application can recognize leading continuous bytes as valid application payload. For messaging protocols it is a whole message.

# Algorithm
- Logic is different from regular TCP assembler. Handle case "packet dropped by capture". Packet was lost by Probe/Spy/TAP device, tcpdump, wireshark/tshark. This packet was delivered from sender to receiver and therefore will not be retransmitted, but it is missing in the PCAP.
- Keep a hole in TCP assembler and await until it is filled.
- Assembler relies on stable detection of application message by `try_consume_tcp_payload()` callback.
    - TCP segments borders do not designate beginning or end of application message.
    - If segments are lost, then TCP payload will be tested from middle of half-received application message and method `try_consume_tcp_payload()` should reliably reject to consume it.
    - Drop what is not recognized as application message. Inform application about data loss.
- On receive of a TCP segment, store it in the receive_buffer and in tcp_assembler.
- Consume messages ONLY from beginning of receive_buffer until next hole in receive_buffer.
- Do not use Ring Buffer. Implementations based on a Ring Buffer moves task of detecting message beginning to the application. Each application need to implement a logic to detect message beginning.

# Leading hole
 - Until leading hole is present in receive_buffer - do not try to consume payload.
 - Allocate receive_buffer, which is larger, than actual TCP Receive Window.
 - Idea is, that if receive_buffer large enough and packets were received to fill it completely, then likely leading hole will be never filled. Packet is missed in a PCAP (not on wire).
 - So wait for retransmission only until receive buffer is full, after that give up, drop leading hole and try to consume. Next, please see "Detect message beginning".

# Detect message beginning
- Main idea is that Application can **refuse to consume.** 
    - This is a big difference to regular TCP stack. 
    - This will allow to iterate over receive_buffer and try to find a message beginning by calling `try_consume_tcp_payload()` application callback.
- When receive_buffer has data and no leading hole, then call `try_consume_tcp_payload()`. Give a full slice of continuous data from beginning of receive_buffer. If application cannot recognize beginning of a message, then callback will return 0. Do nothing, wait for next segment
- When new data arrives call `try_consume_tcp_payload()` once again, with a whole slice of continuous data from beginning of receive_buffer.
- When receive buffer is full. Then try to find a message beginning by calling `try_consume_tcp_payload()` trying to consume starting from each byte in receive_buffer.
    - Iterate bytes from beginning of receive_buffer to the end
    - Build a slice from current iterator position to the end of receive_buffer. Call `try_consume_tcp_payload()` with such slice.
    - As soon as `try_consume_tcp_payload()` callback returns non zero value, that means message beginning is found by application callback.
    - Drop data on left end call `inform_packet_loss()` callback.
    - Copy unconsumed data on right to the buffer B.
 
# Implementation
- Allocate two  buffers: A and B. Work only with one of them at a time.
- Use two receive buffers and rotate them, instead of ring buffer.
- MARKER.
- Write data to the buffer A.
- If no Leading hole, then try to consume only from Head. If not consumed continue with next segment.
- If Leading hole is present, then fill buffer A so long, until next segment is not fitting in it. Do not try to consume until buffer A is full.
- When buffer A is full, try to consume.
- Leading hole is a missing data and it will not be awaited anymore.
- Skip leading whole and start to consume from from first byte after leading hole to the end if of continuous bytes range.
    - If not consumed, start from second byte and so on.
    - If consumed. Discard left bytes if any. Report them as lost. Copy remaining bytes to buffer B. Start over with B from MARKER.
- If middle hole is reached. Copy all not consumed bytes to the buffer B, from position of beginning of middle hole to the end of buffer A. Start over with B.
- If end of buffer A reached and data is not consumed:
    - If leading hole present, copy to the buffer B everything after leading hole. Do not discard content! Start over with B.
    - If leading hole not present, clear buffer A. Start over with A.

# try_consume_tcp_payload() callback
- Callback should reliably detect beginning of the message.
- Callback should reliably reject unrecognizable message.
- Callback should use minimal necessary amount of message bytes to decide if it is a valid message or not. Not to wait until full message arrives.
- HTTP example:
    - Callback should only try to recognize a beginning of HTTP message. Do not wait until all headers are received.
    - For HTTP 1/1, 8 bytes is a minimal size needed to recognize a message beginning
    - After HTTP message beginning is recognized callback should start to buffer received data and return non zero value
- Callback should buffer TCP payload after it has recognized message binning, for further message parsing.

# Benefits
- Await for missing data as much as possible.

# Drawbacks
- Data copying.
    - Not avoidable, because application need a continuous buffer to consume

# Notes
- For use case, like file download, when data loss is could be not acceptable, application should somehow skip forward to the next file or try to recover payload somehow.
- For messaging protocols, application should account dropped messages.