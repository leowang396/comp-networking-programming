"""
Project 3: Raw Sockets
"""

from socket import *
from struct import *
import sys
import argparse

_TEST_URL = "http://david.choffnes.com/classes/cs5700f22/project3.php"
_BUFFER_SIZE = 65565  # Max possible TCP segment size.
_IP_ID = 54321 # Identification number for single IP connection.
_TCP_SEQ_NUM = 454 # Non-random TCP sequence number for test purpose.
# useless notes:
# use \xaa as a shorthand to transform 0xaa into strings. only 2 digits allowed.

# TODO: For the current commit, build a coherent receiver.

def checksum_veri(ip_header):
    """
    Verify the IPv4 header checksum. Return True if correct; False otherwise.
    Examples can be found in "https://en.wikipedia.org/wiki/Internet_checksum#cite_note-7"
    """
    iph = unpack('!HHHHHHHHHH' , ip_header)
    checksum = sum(iph)
    while checksum.bit_length() > 16:
        moving_digits = checksum.bit_length()
        carry_bit = checksum >> moving_digits  # Find the first digit of the checksum.
        checksum += carry_bit
    if ~checksum & 0xFFFF != 0x0: # Flip all bits. Correct if result is 0x0000 = 0x0.
        return False
    else:
        return True


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


def filter_pckt(ip_header, expected_addr, addr, version, iph_length, id, ip_id, protocol, s_addr, d_addr):
    """
    # TODO: filter not working properly. Result: source: 127.0.0.1, dest: 127.0.0.1, filter flag: False

    Filter criteria: Src/Dest IP address, TCP protocol, TCP dest port number.

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


def ip_builder(ip_id, s_addr, d_addr):
    """
    Build & return a IP header for packets to be sent.
    
    Args:
        ip_id: An int representing the identification of this IP connection.
        s_addr: A string of source IP address in dotted quad-string format.
        d_addr: A string of dest IP address in dotted quad-string format.
    Returns:
        A string of binary values as the IP header.
    """
    # IP header fields
    ip_ver = 4
    ip_ihl = 5
    ip_ver_ihl = (ip_ver << 4) + ip_ihl

    ip_tos = 0
    ip_tot_len = 0 # Kernel will fill the correct total length
    ip_frag_off = 0
    ip_ttl = 255
    ip_proto = IPPROTO_TCP
    ip_check = 0 # Kernel will fill the correct checksum
    ip_saddr = inet_aton(s_addr) # Source IP address in 32-bit packed binary format.
    ip_daddr = inet_aton(d_addr) # Dest IP address in 32-bit packed binary format.
    # Or socket.gethostbyname('www.google.com')

    # the ! in the pack format string means network order
    ip_header = pack('!BBHHHBBH4s4s' , ip_ver_ihl, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
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
    print("TCP checksum result:", tcp_checksum)

    # make the tcp header again and fill the correct checksum - remember checksum is NOT in network byte order
    tcp_header = pack('!HHLLBBH' , tcp_source_port, tcp_dest_port, tcp_seq_num, tcp_ack_num, tcp_offset_res, tcp_flags, tcp_window) + pack('H' , tcp_checksum) + pack('!H' , tcp_urg_ptr)
    return tcp_header


def data_builder(empty, data):
    """
    # TODO: Build a HTTP data for packets to be sent, including packets for 3-way handshakes and ACK packets after that.
    """
    pass


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
    Unpacks an bytes object representing data received from the socket. Return a list that contains a filter flag & the TCP header + data.

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
    s_addr = inet_ntoa(iph[8]) # Converts an IP address to dotted quad-string format.
    d_addr = inet_ntoa(iph[9])

    # Filter for packets we are interested in.
    filter_flag = filter_pckt(ip_header, expected_addr, addr, version, iph_length, id, ip_id, protocol, s_addr, d_addr)
    print('Packet filter result based on IP header:', filter_flag)

    # print('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))
    ip_header_list = [version, ihl, ttl, protocol, s_addr, d_addr]

    return (iph_length, version, ihl, ttl, protocol, s_addr, d_addr)
    # [filter_flag, ip_header_list, pckt[iph_length:]]


def unpack_pckt_tcp(pckt_no_ip):
    """
    Unpacks an bytes object representing data received from the socket, without the IP header.
    
    Defensively unpacks a data packet to retrieve the IP header, TCP header, 
    and data payload information. Leverages the `unpack` function from the 
    `struct` library.

    # TODO: Current version assumes IPv4, the assignment packet might be IPv6 as well.

    Args:
        pckt_no_ip: A bytes object representing data packet received without the IP header.
        addr: Address of the remote socket sending data.
        expected_addr: Address that the client sent data to.

    Returns:
        A list that contains a TCP header list & the data payload.
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
    
    print('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length))
    tcp_header_list = [source_port, dest_port, sequence, acknowledgement, tcph_length]

    # Gets data after the TCP header.
    data = pckt_no_ip[tcph_length * 4:]
    print('Data:', data)

    return [tcp_header_list, data]


def unpack_pckt(pckt, ip_id, expected_addr):
    """Unpacks an bytes object representing data received from the socket.
    
    This should serve as a top-level receiver function that calls other helpers.
    """

    (iph_length, version, ihl, ttl, protocol,
    s_addr, d_addr) = unpack_pckt_ip(pckt)

    unpack_pckt_tcp(pckt[iph_length:])


def main():
    # 80 for http connection. for https, use 443 instead.
    local_port = 80
    # Sets the commandline interface
    parser = argparse.ArgumentParser(description="CS5700 Project 3")
    # initiate a parser for the commandline command
    parser.add_argument("URL", nargs=1)
    # Contains a list of all arguments of the commandline command in args
    args = parser.parse_args()
    # Obtains URL using args.URL[0]
    # Check if URL has the http part. Use as it is if not.
    if args.URL[0][:7] == "http://":
        url = args.URL[0][7:]
    else:
        url = args.URL[0]

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
            
            # 1st SYN packet from local host
            data = "".encode(encoding="utf-8")
            tcp_header = tcp_builder(1107, 80, True, False, 0, 5840, gethostbyname(gethostname()), gethostbyname(_TEST_URL[7:25]), data)
            ip_header = ip_builder(_IP_ID, gethostbyname(gethostname()), gethostbyname(_TEST_URL[7:25]))
            packet = build_pckt(ip_header, tcp_header, data)
            try:
                send_s.send(packet)
            except:
                print("Error: Failed to send 1st SYN packet in the 3-way handshake.")

            counter = 1
            while True:
                print("Packet #" + str(counter) + ":")
                # TODO: How to ensure complete packets are received?
                # This seems no guaranteed for TCP, but the tutorial seems to assume it anyway.
                # https://stackoverflow.com/questions/67509709/is-recvbufsize-guaranteed-to-receive-all-the-data-if-sended-data-is-smaller-th
                filter_flag = False
                while not filter_flag: # Drop the packet if filter_flag is False.
                    packet, addr = recv_s.recvfrom(_BUFFER_SIZE)
                    # TODO: need to fix the following line.
                    # addr = socket.gethostbyname(_TEST_URL[7:]) # Do not include the "http://" part.
                    expected_addr = gethostbyname(gethostname()) # Get local host IP.
                    filter_flag, ip_header_list, pckt_no_ip = unpack_pckt_ip(packet, _IP_ID, addr, expected_addr)
                    print(packet[:20])
                counter += 1
    return


if __name__ == "__main__":
    main()