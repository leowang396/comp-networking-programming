"""Project 3: Raw Sockets
"""
from socket import *
from struct import *
import sys

_TEST_URL = "http://david.choffnes.com/classes/cs5700f22/project3.php"
_BUFFER_SIZE = 65565  # Max possible TCP segment size.

def filter_pckt():
    """TODO: Add a helper to filter for packets we want, i.e. address match, valid IP header, valid checksum.
    """
    return

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
    s_addr = socket.inet_ntoa(iph[8]);
    d_addr = socket.inet_ntoa(iph[9]);

    # TODO: Filter for packets we are interested in.
    # filter_pckt()

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
