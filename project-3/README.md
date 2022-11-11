# Group Information

Name: Jiazhe Chen, NUID: 002162461  
Name: Shengdi Wang, NUID: 002957805

# High Level Approach

## Setting Up Raw Sockets and Connections
To use raw sockets in Python, we created 2 sockets of the types `(SOCK_RAW, IPPROTO_RAW)` and `(SOCK_RAW, IPPROTO_TCP)` as the sending and receiving raw sockets.

To avoid binding our raw sockets to localhost instead of the public IP addresses, we use `socket.connect()` to connect our socket to the remote host, so that we can find out the IP address and port number associated with the socket.

To filter for only the relevant packets from the promiscuous receiving socket, we created a custom FilterRejectException exception type, which is raised if there is a mismatch in IP addresses, port numbers, or protocol type.

## Top-down Programming
We developed the script in a top-down manner, by identifying the key steps and defining separate functions for each. Specifically, we created functions for `set_up_tcp` to handle 3-way handshake, `raw_http_get` to manage the HTTP GET through established TCP connection, and `tear_down_tcp` to tear down the TCP connection.

## Factor Out Utility Functions
We identifies several operations that are frequently applied across the scripts, which includes packing and unpacking of packets and checksum-related operations. We then factor out these operations into separate functions, `pack_raw_http`, `unpack_raw_http`, and `checksum`.

# TCP/IP Features and Detailed Author Description

Initials of feature authors are included in brackets, e.g. (SW), (JC).

## Raw Socket Creation.
Two raw socket instances are used in the "main" function to build the raw socket connection together (SW). One acts as the sender to send data from the client to the server, and the other acts as the receiver to receive data from the server to the client.

## TCP Set Up
After that, the "set_up_tcp" function is used to handle the 3-way handshake process with the server to build the connection. The "pack_raw_http" function and the "unpack_raw_http" function are called in it (SW). The "pack_raw_http" function is responsible for building the SYN packet, including the IP header, the TCP header, and an empty data body (JC). The "build_tcp_head" function and "build_ip_head" function are called in the "pack_raw_http" function. The first one is responsible to build the TCP headers for packets to be sent to the server (JC). The second one is responsible to build the IP headers for packets to be sent to the server (JC). The "unpack_raw_http" function is responsible for receiving the SYN/ACK packet from the receiver socket and unpacking it into corresponding items (SW). After using IP filters and TCP filters to check the SYN/ACK packet received, the packet is unpacked using the "unpack_ip_head" function and the "unpack_tcp_head" function to get IP header items and TCP header items correspondingly (SW). After that, an ACK packet is built and sent to the server using the "pack_raw_http" function (SW). By doing so, the 3-way handshake process is finished if the server sends back an ACK packet that contains the data body in it.  

## HTTP GET Request
The "raw_http_get" function is used to continuously receive data packets from the server and send ACK packets to the server to maintain the data flow (SW). Since the packets sent by the server will not be in order, packets will be discarded if they are out of order (SW). Packets that are not out of order will be collected and saved in the memory so that they can be written into a local file when the connection ends (SW). Flag detection is performed during the process. If a flag that indicates a different state of the connection is detected, the function will handle the situation accordingly, for instance, send a FIN/ACK packet and break out of the connection process when a FIN flag is received (SW). A three-minute timeout is also set for the receiver socket instance so that it can shut up after failing to get any data from the server (SW).  


## TCP Tear Down
At the end of the connection process, the "tear_down_tcp" function is called. It is responsible to build the last FIN/ACK packet and send it to the server, and then wait for the last ACK packet to be received and handle it. The connection will be turned off automatically in the "main" function later after the "tear_down_tcp" function call is finished (SW). The data in the memory will be written into a new file in the local directory using the same name as the URL link (SW).  

# Challenges Faced

## Set Up Raw Socket and TCP Connection
At first, we have trouble sending the raw packets using the raw socket instance correctly. After that, we have trouble getting useful information when unpacking the packets from the server. It took us some time to build the 3-way handshake at first because local IP addresses and local port number configurations are not the same in a virtual Linux system as in the usual operating system.

## Debugging of TCP Packet Transfer
After that, the data-receiving process is also not easy to implement because the client sequence number and the server sequence number mechanism is not as straightforward as it looks. It took us some time to figure out the correct amount to add to the sequence numbers to pass to the server, and then use the acknowledgment number as the sequence number for the next packet to send. Although Wireshark is a really useful tool to have when debugging the project 3 code, it also took us some time to learn and practice, so that we can understand the meaning of the information it provides.

## Requirements Clarification
When we started to work on the project, we did not know if we should handle fragments. We also did not know if it is safe to assume that there are no optional fields in the IP headers and the TCP headers when connecting to the server. We went to the office hours of the teaching assistants to gain some help from them. And in the end, we have managed to overcome the challenges mentioned above and obtain the correct HTML file that has the same SHA256 value as the one obtained by the "wget" command.  