"""Project 3: Raw Sockets
"""
from socket import *
from struct import *
import sys

_TEST_URL = "http://david.choffnes.com/classes/cs5700f22/project3.php"
_BUFFER_SIZE = 65565  # Max possible TCP segment size.

def filter_pckt(iph, host_addr, expected_addr, version, iph_length, protocol, s_addr, d_addr):
    """TODO: Add a helper to filter for packets we want, i.e. address match, valid IP header, valid checksum.
    Filter packets assuming IPv4 & TCP.
    """
    # Verifies IP header format, including version, IP header length and protocol.
    if version != 0x4: # Assuming IPv4.
        return False
    if iph_length != 0x5: # Assuming no optional field.
        return False
    if protocol != 0x06: # Assuming TCP.
        return False
    # Verifies s_addr and d_addr.
    if host_addr != d_addr or expected_addr != s_addr:
        return False
    # Verifies checksum. Return False if verification failed.
    checksum = 0
    moving_digits = 16
    while checksum >> moving_digits == 0x0 and moving_digits > 0: # Find the first digit of the checksum.
        moving_digits -= 4
    carry_bit = checksum >> moving_digits
    checksum += carry_bit
    if ~checksum != 0x0000: # Flip all bits. Correct if result is 0x0000.
        return False
    return True

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

    # TODO: Filter for packets we are interested in.
    # Get local host IP.
    host_addr = socket.gethostbyname(socket.gethostname)
    # Get server IP.
    expected_addr = socket.gethostbyname(_TEST_URL[7:]) # Do not include the "http://" part.
    filter_flag = filter_pckt(iph, host_addr, expected_addr, version, iph_length, protocol, s_addr, d_addr)
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
