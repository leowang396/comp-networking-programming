"""
Project 3: Raw Sockets
"""
import sys
import time
import socket
import struct
from urllib.parse import urlparse

_TEST_URL = "http://david.choffnes.com/classes/cs5700f22/project3.php"
_BUFFER_SIZE = 65565  # Max possible TCP segment size.
_IP_ID = 0xd431 # Identification number for single IP connection. 54321 = 0xd431 for test.
_TCP_SEQ_NUM = 454  # Non-random TCP sequence number for test purpose.
_PORT_NUM = 80  # 80 for http, 443 for https.
_TCP_PROTOCOL_ID = 6  # TCP protocol ID in IP header.
# useless notes:
# use \xaa as a shorthand to transform 0xaa into strings. only 2 digits allowed.
# 0x follows number, means HEX number.
# \x follows number, means HEX ascii characters.

class FilterRejectException(Exception):
    """
    Raised when received packet is not for raw HTTP GET.
    """
    pass


def checksum(msg):
    """
    checksum functions needed for checksum calculation in IP header & TCP header
    # calculation logic checked

    Args:
        msg: a binary object
    Returns:
        a four digit hex number
    """
    s = 0

    # loop taking 2 characters at a time
    for i in range(0, len(msg), 2):
        # in python3, b"abc"[1] = 98. so no need for ord()
        w = msg[i] + (msg[i+1] << 8)
        s = s + w
    
    s = (s >> 16) + (s & 0xffff)
    s = s + (s >> 16)
    
    # complement and mask to 4 byte short
    s = ~s & 0xffff
    
    return s


def checksum_veri(ip_header):
    """
    Verify the IPv4 header checksum. Return True if correct; False otherwise.
    Examples can be found in "https://en.wikipedia.org/wiki/Internet_checksum#cite_note-7"
    """
    iph = struct.unpack('!HHHHHHHHHH' , ip_header)
    checksum = sum(iph)
    while ip_check.bit_length() > 15:
        moving_digits = ip_check.bit_length() // 4 * 4
        carry_bit = ip_check >> moving_digits  # Find the first digit of the ip_check.
        ip_check = (ip_check & ((1 << moving_digits) - 1)) + carry_bit # add the rest and the first digit
    if ~ip_check & 0xFFFF != 0x0: # Flip all bits. Correct if result is 0x0000 = 0x0.
        return False
    else:
        return True


def ip_builder(ip_id, data_length, protocol, s_addr, d_addr):
    """
    Build & return a IP header for packets to be sent.
    Args:
        ip_id: An int representing the identification of this IP connection.
        data_length: int for length of data other than IP header part.
        protocol: int for protocol number. 6 as TCP.
        s_addr: A string of source IP address in dotted quad-string format.
        d_addr: A string of dest IP address in dotted quad-string format.
    Returns:
        A string of binary values as the IP header.
    """
    # IP header fields
    ip_ver_ihl = 0x45
    ip_tos = 0x00
    ip_tot_len = 0x0 # kernel will fill the correct total length
    # ip_id here
    ip_frag_off = 0x0000
    ip_ttl = 0xff # 255
    ip_proto = protocol
    ip_check = 0 # kernel will fill the correct checksum
    ip_saddr = inet_aton(s_addr)
    ip_daddr = inet_aton(d_addr)

    # the ! in the pack format string means network order
    ip_header = pack('!BBHHHBBH4s4s' , ip_ver_ihl, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)

    # print("IP header checksum", hex(checksum(ip_header)))
    # print("Source IP address:", s_addr)
    # print("Dest IP address:", d_addr)

    return ip_header


def tcp_builder(source_port, dest_port, syn, ack, ack_num, window_size, s_addr, d_addr, data):
    """
    Build & return a TCP header for packets to be sent, including packets for 3-way handshakes and ACK packets after that.
    Args:
        source_port: An int representing the source end port number. The local port number listened by the sender. e.g. 1234
        dest_port: An int representing the destination end port number. The remote port number listened by the receiver. e.g. 80 for http traffic.
        syn: A boolean representing the SYN flag. True if SYN flag == 1;
        ack: A boolean representing the ACK flag. True if ACK flag == 1;
        ack_num: An int representing the ACK number in current packet. Calculated using seq_num of last packet ACKed + 1.
        window_size: 
        ip_id: An int representing the identification of this IP connection.
        s_addr: A string of source IP address in dotted quad-string format.
        d_addr: A string of dest IP address in dotted quad-string format.
    Returns:
        A string of binary values as the TCP header.
    """
    # TCP header fields
    tcp_source_port = source_port # source port
    tcp_dest_port = dest_port # destination port, 80 if http traffic
    tcp_seq_num = _TCP_SEQ_NUM # TODO: use a random number here. for test purpose, use _TCP_SEQ_NUM instead.
    tcp_ack_num = ack_num # should be the seq_num from last packet received + 1
    tcp_doff = 5 # 4 bit field, size of tcp header, 5 * 4 = 20 bytes if no optional field
    # TCP flags
    tcp_fin = 0
    if syn:
        tcp_syn = 1
    else:
        tcp_syn = 0
    tcp_rst = 0
    tcp_psh = 0
    if ack:
        tcp_ack = 1
    else:
        tcp_ack = 0
    tcp_urg = 0
    # window size should be passed from outside by a congestion control function
    tcp_window = socket.htons(window_size) # 5840 is the maximum allowed window size
    # socket.htons() is for little-endian machines. See link below for examples.
    # https://stackoverflow.com/questions/19207745/htons-function-in-socket-programing
    # how to know if the machine is little-endian or not? See link below for command.
    # https://serverfault.com/questions/163487/how-to-tell-if-a-linux-system-is-big-endian-or-little-endian
    tcp_checksum = 0 # use checksum function to calculate it later
    tcp_urg_ptr = 0

    tcp_offset_res = (tcp_doff << 4) + 0 # 0 is for NS flag. Use 1 if NS flag is 1.
    tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5) # note that TCP flags are in reverse order

    # the ! in the pack format string means network order
    tcp_header = pack('!HHLLBBHHH' , tcp_source_port, tcp_dest_port, tcp_seq_num, tcp_ack_num, tcp_offset_res, tcp_flags, tcp_window, tcp_checksum, tcp_urg_ptr)

    # pseudo IP header fields for checksum calculation
    source_address = socket.inet_aton(s_addr) # Converts an IP address from dotted quad-string format to 32-bit packed binary format.
    dest_address = socket.inet_aton(d_addr)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header) + len(data)

    psh = struct.pack('!4s4sBBH', source_address, dest_address, placeholder, protocol, tcp_length)
    psh = psh + tcp_header + data

    tcp_checksum = checksum(psh)
    # print("TCP checksum result:", tcp_checksum)

    # make the tcp header again and fill the correct checksum - remember checksum is NOT in network byte order
    tcp_header = struct.pack('!HHLLBBH' , tcp_source_port, tcp_dest_port, tcp_seq_num, tcp_ack_num, tcp_offset_res, tcp_flags, tcp_window) + struct.pack('H' , tcp_checksum) + struct.pack('!H' , tcp_urg_ptr)
    return tcp_header


def unpack_pckt_ip(pckt):
    """Unpacks an bytes object representing data received from the socket.
    
    Return a list of TCP header details. Raises a FilterRejectException if 
    non-TCP protocol is detected.
    Args:
        pckt: A bytes object representing data packet received.
        id: Identification for the current connection.
        addr: Address of the remote socket sending data.
        expected_addr: Address that the client sent data to.
    Returns:
        A list that contains a filter flag, a IP header list & the TCP header + data as a string.
            The filter flag is True when the packet is verified to be wanted ones. Drop the packet if False.
    """
    # Unpacks the first 20 bytes for the IP header.
    ip_header = pckt[0:20]
    iph = struct.unpack('!BBHHHBBH4s4s' , ip_header)
    # elements in iph: 0 is version & IHL; 1 is DSCP & ECN; 2 is total length; 3 is IP id; 4 is flags & frag-offset;
    # 5 is TTL; 6 is protocol; 7 is IP header checksum; 8 is source IP address; 9 is dest IP address;

    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
    iph_length = ihl * 4  # Header length in bytes.

    id = iph[3]
    ttl = iph[5]
    protocol = iph[6]
    # Converts addrs to dotted quad-string format.
    s_addr = socket.inet_ntoa(iph[8])
    d_addr = socket.inet_ntoa(iph[9])

    # Filters out non-TCP packets.
    if protocol != _TCP_PROTOCOL_ID:
        raise FilterRejectException

    return (iph_length, version, ihl, id, ttl, protocol, s_addr, d_addr)


def unpack_pckt_tcp(pckt_no_ip):
    """Unpacks TCP header of an bytes object.
    
    Defensively unpacks a data packet to retrieve the TCP header information. 
    Leverages the `unpack` function from the `struct` library.

    Args:
        pckt_no_ip: A bytes object of data packet after truncating IP header.

    Returns:
        A list that contains a TCP header tuple.
    """
    # Unpacks the 20 bytes after IP header for the TCP header.
    tcp_header = pckt_no_ip[0:20]
    tcph = struct.unpack('!HHLLBBHHH' , tcp_header)
    
    source_port = tcph[0]
    dest_port = tcph[1]
    sequence = tcph[2]
    acknowledgement = tcph[3]
    doff_reserved = tcph[4]
    tcph_length = doff_reserved >> 4
    tcph_length *= 4  # Use same unit as the iph_length in IP header.

    return (tcph_length, sequence, acknowledgement, source_port, dest_port)


def unpack_raw_http(pckt, remote_hostname, app_port_num):
    """Unpacks an bytes object representing HTTP data received from raw socket.
    
    This should serve as a top-level receiver function that calls other helpers.
    """
    # IP-level unpacking.
    (iph_length, version, ihl, id, ttl, protocol,
    s_addr, d_addr) = unpack_pckt_ip(pckt)

    # IP-level filter for packets for this app.
    if (s_addr != socket.gethostbyname(remote_hostname)
    or d_addr != socket.gethostbyname(socket.gethostname())):
        raise FilterRejectException

    # TCP-level unpacking.
    (tcph_length, sequence, acknowledgement,
    source_port, dest_port) = unpack_pckt_tcp(pckt[iph_length:])

    # TCP-level filter for packets for this app.
    if app_port_num != dest_port:
        raise FilterRejectException

    return pckt[(iph_length + tcph_length):]


def tear_down_tcp(sends, recvs, remote_hostname):
    pass


def set_up_tcp(sends, recvs, remote_hostname):
    # 1st SYN packet from local host. Use _TEST_URL for test purpose.
    data = "".encode(encoding="utf-8")
    # "10.0.0.98" is local IP address got by Wireshark. Somehow this is different than get method result
    tcp_header = tcp_builder(_LOCAL_PORT_NUM, 80, True, False, 0, 5840, gethostbyname(gethostname()), gethostbyname(url_hostname), data)
    # print("TCP header:", tcp_header)
    ip_header = ip_builder(_IP_ID, 20 + len(data), IPPROTO_TCP, gethostbyname(gethostname()), gethostbyname(url_hostname))
    # print("IP header:", ip_header)
    packet = build_pckt(ip_header, tcp_header, data)
    # SYN sent successfully
    try:
        send_s.sendto(packet, (gethostbyname(url_hostname), 0))
        print("Send 1st SYN packet successfully!")
    except:
        print("Error: Failed to send 1st SYN packet in the 3-way handshake.")
        send_s.close()


def raw_http_get(sends, recvs, remote_hostname):
    counter = 1  # DEBUG
    while True:
        packet, addr = recv_s.recvfrom(_BUFFER_SIZE)
        
        # TODO: How to ensure complete packets are received?
        # This seems no guaranteed for TCP, but the tutorial seems to assume it anyway.
        # https://stackoverflow.com/questions/67509709/is-recvbufsize-guaranteed-to-receive-all-the-data-if-sended-data-is-smaller-th

        try:
            filter_flag, ip_header_list, pckt_no_ip = unpack_raw_http(packet, parsed_url.hostname, send_s.getsockname()[1])

            print("Packet #" + str(counter) + ":")  # DEBUG
            counter += 1
        # Checks if the packet is intended for other processes.
        except FilterRejectException:
            pass
        # Checks if a packet intended for our app is illegal.
        # TODO: Add such checks.
        except Exception as e:
            print("Error: Illegal response received!")
            print(e)


def main():
    args = sys.argv[1:]
    url = args[0] if args else _TEST_URL  # Expects no or exactly one arg.
    parsed_url = urlparse(url)
    url_hostname = parsed_url.hostname

    # Creates a raw socket for sending packets.
    with socket.socket(
        socket.AF_INET,
        socket.SOCK_RAW,
        socket.IPPROTO_RAW
        ) as send_s:
        if (send_s == -1):
            print("Error: Raw sending socket creation failed,"
            + " check privileges.")
            exit(1)

        # Creates a raw socket for receiving packets.
        with socket.socket(
            socket.AF_INET,
            socket.SOCK_RAW,
            socket.IPPROTO_TCP
            ) as recv_s:
            if (recv_s == -1):
                print("Error: Raw receiving socket creation failed,"
                + " check privileges.")
                exit(1)

            # Binds receiving socket to IP interface.
            # recv_s.bind((gethostbyname(gethostname()), 0))

            # TODO: Add a 3-min timer for all receiving operations.
            # time_out_time = time.time() + 180

            (send_seq, recv_seq) = set_up_tcp(send_s, recv_s, url_hostname)

            (raw_http_get_res, send_seq, recv_seq) = raw_http_get(send_s, 
            recv_s, url_hostname, send_seq, recv_seq)

            # TODO: Convert 'raw_http_get_res' into HTML and save it.

            tear_down_tcp(send_s, recv_s, url_hostname, send_seq, recv_seq)
    
    return


if __name__ == "__main__":
    main()