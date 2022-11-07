"""
Project 3: Raw Sockets
"""

from socket import *
from struct import *
import sys
import argparse

_TEST_URL = "http://david.choffnes.com/classes/cs5700f22/project3.php"
_BUFFER_SIZE = 65565  # Max possible TCP segment size.
_IP_ID = 54321  # Identification number for single IP connection.


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


def filter_pckt(ip_header, expected_addr, addr, version, iph_length, id, ip_id, protocol, s_addr, d_addr):
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
    Build a IP header for packets to be sent.
    
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
    ip_proto = socket.IPPROTO_TCP
    ip_check = 0 # Kernel will fill the correct checksum
    ip_saddr = socket.inet_aton(s_addr) # Source IP address in 32-bit packed binary format.
    ip_daddr = socket.inet_aton(d_addr) # Dest IP address in 32-bit packed binary format.
    # Or socket.gethostbyname('www.google.com')

    # the ! in the pack format string means network order
    ip_header = pack('!BBHHHBBH4s4s' , ip_ver_ihl, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
    return ip_header


def tcp_builder():
    """
    # TODO: Build a TCP header for packets to be sent, including packets for 3-way handshakes and ACK packets after that.
    """
    pass


def data_builder():
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


def unpack_pckt_ip(pckt, ip_id, addr, expected_addr):
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
    s_addr = socket.inet_ntoa(iph[8]) # Converts an IP address to dotted quad-string format.
    d_addr = socket.inet_ntoa(iph[9])

    # Filter for packets we are interested in.
    filter_flag = filter_pckt(ip_header, expected_addr, addr, version, iph_length, id, ip_id, protocol, s_addr, d_addr)
    print('Packet filter result based on IP header: ' + filter_flag)

    print('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))
    ip_header_list = [version, ihl, ttl, protocol, s_addr, d_addr]

    return [filter_flag, ip_header_list, pckt[iph_length:]]


def unpack_pckt_tcp(pckt_no_ip, addr, expected_addr):
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
    print('Data : ' + data)

    return [tcp_header_list, data]


def main():
    # 80 for http connection. for https, use 443 instead.
    port = 80
    # Sets the commandline interface
    parser = argparse.ArgumentParser(description="CS5700 Project 3")
    # initiate a parser for the commandline command
    parser.add_argument("URL", nargs=1)
    # Contains a list of all arguments of the commandline command in args
    args = parser.parse_args()
    # Obtains URL using args.URL[0]

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

            counter = 1
            while True:
                print("Packet #" + str(counter) + ":")
                # TODO: How to ensure complete packets are received?
                # This seems no guaranteed for TCP, but the tutorial seems to assume it anyway.
                # https://stackoverflow.com/questions/67509709/is-recvbufsize-guaranteed-to-receive-all-the-data-if-sended-data-is-smaller-th
                filter_flag = False
                while not filter_flag: # Drop the packet if filter_flag is False.
                    packet, addr = recv_s.recvfrom(_BUFFER_SIZE)
                    addr = socket.gethostbyname(_TEST_URL[7:]) # Do not include the "http://" part.
                    expected_addr = socket.gethostbyname(socket.gethostname) # Get local host IP.
                    filter_flag, ip_header_list, pckt_no_ip = unpack_pckt_ip(pckt, _IP_ID, addr, expected_addr)
                counter += 1
    return


if __name__ == "__main__":
    main()