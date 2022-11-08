"""
Project 3: Raw Sockets
"""
import sys
import time
from socket import *
from struct import *
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

# TODO: For the current commit, build a coherent receiver.


class FilterRejectException(Exception):
    """
    Raised when received packet is not for raw HTTP GET.
    """
    pass


def checksum(msg):
    """
    checksum functions needed for checksum calculation
    # TODO: need to check the calculation logic
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
    iph = unpack('!HHHHHHHHHH' , ip_header)
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
    # TODO: need to handle fragments
    # TODO: check to see if fixed
    # Example result: b'E\x00\x00(
                        \xab\xcd\x00\x00
                        @\x06\xa6\xec
                        \n\n\n\x02
                        \n\n\n\x01'
    # Current result: b'E\x00\x00(
                        \xd41\x00\x00
                        \xff\x06\xdb3
                        \x7f\x00\x01\x01
                        \xcc,\xc0<'
                        
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
    # e.g.
    # ip_header  = b'\x45\x00\x00\x28'  # Version, IHL, Type of Service | Total Length
    # ip_header += b'\xab\xcd\x00\x00'  # Identification | Flags, Fragment Offset
    # ip_header += b'\x40\x06\xa6\xec'  # TTL, Protocol | Header Checksum
    # ip_header += b'\x0a\x0a\x0a\x02'  # Source Address
    # ip_header += b'\x0a\x0a\x0a\x01'  # Destination Address
    # Might need to use htons() to convert 0-65535(0xFFFF) to network byte order.
    # See https://www.ibm.com/docs/en/zvm/6.4?topic=SSB27U_6.4.0/com.ibm.zvm.v640.kiml0/asonetw.htm
    ip_ver_ihl = 0x45
    ip_tos = 0x00
    ip_tot_len = data_length + 20
    # ip_id here
    ip_frag_off = 0x0000
    ip_ttl = 0xff
    ip_proto = protocol
    # ip_check here
    (first, second, third, fourth) = s_addr.split('.')
    first_saddr = int(first)
    second_saddr = int(second)
    third_saddr = int(third)
    fourth_saddr = int(fourth)
    # Use int_to_hex(first_saddr, 4) later

    (first, second, third, fourth) = d_addr.split('.')
    first_daddr = int(first)
    second_daddr = int(second)
    third_daddr = int(third)
    fourth_daddr = int(fourth)

    # IP checksum calculation. Examples can be found in "https://en.wikipedia.org/wiki/Internet_checksum#cite_note-7"
    ip_check = ((ip_ver_ihl << 8) + ip_tos) + \
                ip_tot_len + \
                ip_id + \
                ip_frag_off + \
                ((ip_ttl << 8) + ip_proto) + \
                ((first_saddr << 8) + second_saddr) + \
                ((third_saddr << 8) + fourth_saddr) + \
                ((first_daddr << 8) + second_daddr) + \
                ((third_daddr << 8) + fourth_daddr)
    if ip_check.bit_length() > 15:
        moving_digits = ip_check.bit_length() // 4 * 4
        carry_bit = ip_check >> moving_digits  # Find the first digit of the ip_check.
        ip_check = (ip_check & ((1 << moving_digits) - 1)) + carry_bit # add the rest and the first digit
    ip_check = ~ip_check & 0xFFFF
    
    # e.g. bytes([0x65]) == b'e', only 2 hex digits allowed
    ip_header = b''
    ip_header += bytes([ip_ver_ihl]) # Version, IHL
    ip_header += bytes([ip_tos]) # Type of Service
    ip_header += bytes([(ip_tot_len >> 8)]) # Total Length
    ip_header += bytes([(ip_tot_len & ((1 << 8) - 1))]) # Total Length
    ip_header += bytes([(ip_id >> 8)]) # Identification
    ip_header += bytes([(ip_id & ((1 << 8) - 1))]) # Identification
    ip_header += bytes([(ip_frag_off >> 8)]) # Flags, Fragment Offset
    ip_header += bytes([(ip_frag_off & ((1 << 8) - 1))]) # Flags, Fragment Offset
    ip_header += bytes([ip_ttl]) # TTL
    ip_header += bytes([ip_proto]) # Protocol
    ip_header += bytes([(ip_check >> 8)]) # Header Checksum
    ip_header += bytes([(ip_check & ((1 << 8) - 1))]) # Header Checksum
    ip_header += bytes([first_saddr]) # Source Address
    ip_header += bytes([second_saddr]) # Source Address
    ip_header += bytes([third_saddr]) # Source Address
    ip_header += bytes([fourth_saddr]) # Source Address
    ip_header += bytes([first_daddr]) # Destination Address
    ip_header += bytes([second_daddr]) # Destination Address
    ip_header += bytes([third_daddr]) # Destination Address
    ip_header += bytes([fourth_daddr]) # Destination Address

    print("Source IP address:", s_addr)
    print("Dest IP address:", d_addr)

    return ip_header


def tcp_builder(source_port, dest_port, syn, ack, ack_num, window_size, s_addr, d_addr, data):
    """
    Build & return a TCP header for packets to be sent, including packets for 3-way handshakes and ACK packets after that.
    # TODO: Broken. Current result: b'\x04S\x00P\x00\x00\x01\xc6\x00\x00\x00\x00P\x02\xd0\x16\xcc\xf8\x00\x00'
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
    tcp_window = htons(window_size) # 5840 is the maximum allowed window size
    # socket.htons() is for little-endian machines. See link below for examples.
    # https://stackoverflow.com/questions/19207745/htons-function-in-socket-programing
    # how to know if the machine is little-endian or not? See link below for command.
    # https://serverfault.com/questions/163487/how-to-tell-if-a-linux-system-is-big-endian-or-little-endian
    tcp_checksum = 0 # use checksum function to calculate it later
    tcp_urg_ptr = 0

    tcp_offset_res = (tcp_doff << 4) + 0 # 0 is for NS flag. Use 1 if NS flag is 1.
    tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh <<3) + (tcp_ack << 4) + (tcp_urg << 5) # note that TCP flags are in reverse order

    # the ! in the pack format string means network order
    # Assume no option fields
    tcp_header = pack('!HHLLBBHHH' , tcp_source_port, tcp_dest_port, tcp_seq_num, tcp_ack_num, tcp_offset_res, tcp_flags, tcp_window, tcp_checksum, tcp_urg_ptr)

    # pseudo IP header fields for checksum calculation
    source_address = inet_aton(s_addr) # Converts an IP address from dotted quad-string format to 32-bit packed binary format.
    dest_address = inet_aton(d_addr)
    placeholder = 0
    protocol = IPPROTO_TCP
    tcp_length = len(tcp_header) + len(data)

    psh = pack('!4s4sBBH', source_address, dest_address, placeholder, protocol, tcp_length)
    psh = psh + tcp_header + data

    tcp_checksum = checksum(psh)
    # print("TCP checksum result:", tcp_checksum)

    # make the tcp header again and fill the correct checksum - remember checksum is NOT in network byte order
    tcp_header = pack('!HHLLBBH' , tcp_source_port, tcp_dest_port, tcp_seq_num, tcp_ack_num, tcp_offset_res, tcp_flags, tcp_window) + pack('H' , tcp_checksum) + pack('!H' , tcp_urg_ptr)
    return tcp_header


def build_pckt(ip_header, tcp_header, data):
    """
    Build & return a packet using given IP header, TCP header & data.
    Args:
        ip_header: A string of binary values as the IP header.
        tcp_header: A string of binary values as the TCP header.
        data: A string of binary values as the data payload.
    Returns:
        A string of binary values as the a packet.
    """
    return ip_header + tcp_header + data


def unpack_pckt_ip(pckt):
    """
    Unpacks an bytes object representing data received from the socket. Return a tuple that contains IP header.
    Args:
        pckt: A bytes object representing data packet received.
    Returns:
        A tuple that contains a IP header tuple.
    """
    # Unpacks the first 20 bytes for the IP header. Assuming no option field.
    ip_header = pckt[0:20]
    iph = unpack('!BBHHHBBH4s4s' , ip_header)
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
    s_addr = inet_ntoa(iph[8])
    d_addr = inet_ntoa(iph[9])

    return (iph_length, version, ihl, ttl, protocol, s_addr, d_addr)


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
    tcph = unpack('!HHLLBBHHH' , tcp_header)
    
    source_port = tcph[0]
    dest_port = tcph[1]
    sequence = tcph[2]
    acknowledgement = tcph[3]
    doff_reserved = tcph[4]
    tcph_length = doff_reserved >> 4
    tcph_length *= 4 # Use same unit as the iph_length in IP header.
    
    # print('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length))
    # tcp_header_list = [source_port, dest_port, sequence, acknowledgement, tcph_length]

    # Gets data after the TCP header.
    data = pckt_no_ip[tcph_length * 4:]

    return (tcph_length, sequence, acknowledgement, source_port, dest_port)


# Filter criteria: Src/Dest IP address, TCP protocol, TCP dest port number.
# def filter_pckt_ip(ip_header, expected_addr, addr, version, iph_length, id, ip_id, protocol, s_addr, d_addr):
    """
    A helper function to filter for packets we want, i.e. address match, valid IP header, valid checksum.
    Filter packets assuming IPv4 & TCP. Return True if the packet is a wanted packet; False otherwise.
    Args:
        ip_header: A string that represents the IP header part. Assume 20 bytes with no optional field.
        expected_addr: A string that represents the IP address of the local host. e.g. "10.0.0.98".
        addr: A string that represents the IP address of the remote server to get file from. e.g. "142.251.32.100".
        version: A hex value that represents the version of the IP protocol. e.g. 0x4.
        iph_length: A hex value that represents the IP header length. e.g. 0x5 * 4 = 0x14.
        protocol: A hex value that represents the type of the protocol after the IP header. e.g. 0x06 for TCP.
        s_addr: A string that represents the source address obtained from the IP header.
        d_addr: A string that represents the destination address obtained from the IP header.
    Returns:
        A boolean value. True if the packet is a wanted packet; False otherwise.
    """
    # Verifies IP header format, including version, IP header length and protocol.
    if version != 0x4: # Assuming IPv4.
        return False
    # TODO: Is this a fair assumption?
    if iph_length != 0x14: # Assuming no optional field. 0x5 * 4 = 0x14.
        return False
    if id != ip_id: # Check id in ip_header equals to ip_id = _IP_ID.
        return False
    if protocol != 0x06: # Assuming TCP.
        return False
    # Verifies s_addr and d_addr.
    if host_addr != d_addr or expected_addr != s_addr:
        return False
    # Verifies IP header checksum. Return False if verification failed. True otherwise.
    return checksum_veri(ip_header)


def unpack_raw_http(pckt, remote_hostname):
    """Unpacks an bytes object representing HTTP data received from raw socket.
    
    This should serve as a top-level receiver function that calls other helpers.
    """

    # IP-level unpacking.
    (iph_length, version, ihl, ttl, protocol,
    s_addr, d_addr) = unpack_pckt_ip(pckt)

    # IP-level filter for packets for this app.
    if (s_addr != socket.gethostbyname(remote_hostname)
    or d_addr != socket.gethostbyname(socket.gethostname())):
        raise FilterRejectException

    unpack_pckt_tcp(pckt[iph_length:])

    # TODO: Add TCP-level unpacking and filter.


def main():
    args = sys.argv[1:]
    url = args[0] if args else _TEST_URL  # Expects no or exactly one arg.
    parsed_url = urlparse(url)
    url_hostname = parsed_url.hostname
    url_port = parsed_url.port

    # Creates a raw socket for sending packets.
    with socket(AF_INET, SOCK_RAW, IPPROTO_RAW) as send_s:
        if (send_s == -1):
            print("Error: Raw sending socket creation failed,"
            + " check privileges.")
            exit(1)

        # Creates a raw socket for receiving packets.
        with socket(AF_INET, SOCK_RAW, IPPROTO_TCP) as recv_s:
            if (recv_s == -1):
                print("Error: Raw receiving socket creation failed,"
                + " check privileges.")
                exit(1)

            # Binds receiving socket to IP interface.
            # recv_s.bind((gethostbyname(gethostname()), 0))
            
            # 1st SYN packet from local host. Use _TEST_URL for test purpose.
            data = "".encode(encoding="utf-8")
            tcp_header = tcp_builder(1107, 80, True, False, 0, 5840, gethostbyname(gethostname()), gethostbyname(url_hostname), data)
            print("TCP header:", tcp_header)
            # TODO: use len(tcp_header) + len(data) later after finished TCP header debugging.
            ip_header = ip_builder(_IP_ID, 20 + len(data), IPPROTO_TCP, gethostbyname(gethostname()), gethostbyname(url_hostname))
            print("IP header:", ip_header)
            packet = build_pckt(ip_header, tcp_header, data)
            # TODO: SYN sending failed. Checking now.
            try:
                send_s.send(packet)
                print("Send 1st SYN packet successfully!")
            except:
                print("Error: Failed to send 1st SYN packet in the 3-way handshake.")
                send_s.close()

            # TODO: Add a 3-min timer for server response.
            # time_out_time = time.time() + 180

            counter = 1  # For debugging only.
            while True:
                packet, addr = recv_s.recvfrom(_BUFFER_SIZE)
                
                # TODO: How to ensure complete packets are received?
                # This seems no guaranteed for TCP, but the tutorial seems to assume it anyway.
                # https://stackoverflow.com/questions/67509709/is-recvbufsize-guaranteed-to-receive-all-the-data-if-sended-data-is-smaller-th

                # filter_flag = False
                # while not filter_flag: # Drop the packet if filter_flag is False.
                # addr = socket.gethostbyname(_TEST_URL[7:]) # Do not include the "http://" part.
                # expected_addr = gethostbyname(gethostname()) # Get local host IP.
                try:
                    filter_flag, ip_header_list, pckt_no_ip = unpack_raw_http(packet, parsed_url.hostname, send_s.getsockname()[1])
                    print("Packet #" + str(counter) + ":")
                    counter += 1
                # Checks if the packet is intended for other processes.
                except FilterRejectException:
                    pass
                # Checks if a packet intended for our app is illegal.
                # TODO: Add such checks.
                except Exception as e:
                    print(e)
                    print("Error: Illegal response received!")
    return


if __name__ == "__main__":
    main()