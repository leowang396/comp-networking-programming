"""Project 3: Raw Sockets
"""
from socket import *
from struct import *
import sys

_TEST_URL = "http://david.choffnes.com/classes/cs5700f22/project3.php"
_BUFFER_SIZE = 65565  # Max possible TCP segment size.

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

def filter_pckt(ip_header, host_addr, expected_addr, version, iph_length, protocol, s_addr, d_addr):
    """
    A helper function to filter for packets we want, i.e. address match, valid IP header, valid checksum.
    Filter packets assuming IPv4 & TCP. Return True if the packet is a wanted packet; False otherwise.
    
    Args:
        ip_header: A string that represents the IP header part. Assume 20 bytes with no optional field.
        host_addr: A string that represents the IP address of the local host. e.g. "10.0.0.98".
        expected_addr: A string that represents the IP address of the remote server to get file from. e.g. "142.251.32.100".
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
    if iph_length != 0x14: # Assuming no optional field.
        return False
    if protocol != 0x06: # Assuming TCP.
        return False
    # Verifies s_addr and d_addr.
    if host_addr != d_addr or expected_addr != s_addr:
        return False
    # Verifies checksum. Return False if verification failed. True otherwise.
    return checksum_veri(ip_header)

def unpack_pckt(pckt, addr, expected_addr):
    """Unpacks an bytes object representing data received from the socket.
    
    Defensively unpacks a data packet to retrieve the IP header, TCP header, 
    and data payload information. Leverages the `unpack` function from the 
    `struct` library.

    # TODO: Current version assumes IPv4, the assignment packet might be IPv6 as well.

    Args:
        pckt: A bytes object representing data packet received.
        addr: Address of the remote socket sending data.
        expected_addr: Address that the client sent data to.

    Returns:
        A bytes object representing the data payload.
    """
    # Unpacks the first 20 bytes for the IP header.
    ip_header = pckt[0:20]
    iph = unpack('!BBHHHBBH4s4s' , ip_header)

    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
    iph_length = ihl * 4  # Header length in bytes.

    ttl = iph[5]
    protocol = iph[6]
    s_addr = socket.inet_ntoa(iph[8]) # Converts an IP address to dotted quad-string format.
    d_addr = socket.inet_ntoa(iph[9])

    # Filter for packets we are interested in.
    # Get local host IP.
    host_addr = socket.gethostbyname(socket.gethostname)
    # Get server IP.
    expected_addr = socket.gethostbyname(_TEST_URL[7:]) # Do not include the "http://" part.
    filter_flag = filter_pckt(ip_header, host_addr, expected_addr, version, iph_length, protocol, s_addr, d_addr)
    print('Packet filter result based on IP header: ' + filter_flag)

    print('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))
    
    # Unpacks the 20 bytes after IP header for the TCP header.
    tcp_header = pckt[iph_length:iph_length+20]
    tcph = unpack('!HHLLBBHHH' , tcp_header)
    
    source_port = tcph[0]
    dest_port = tcph[1]
    sequence = tcph[2]
    acknowledgement = tcph[3]
    doff_reserved = tcph[4]
    tcph_length = doff_reserved >> 4
    
    print('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length))

    # Gets data after the TCP header.    
    h_size = iph_length + tcph_length * 4
    data = pckt[h_size:]
    
    print('Data : ' + data)

def main():
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
                packet, addr = recv_s.recvfrom(_BUFFER_SIZE)
                counter += 1

    return

if __name__ == "__main__":
    main()
