"""
Project 3: Raw Sockets
"""
import random
import sys
import socket
import struct
import time
from urllib.parse import urlparse


_TEST_URL = "http://david.choffnes.com/classes/cs5700f22/project3.php"
_BUFFER_SIZE = 65565  # Max possible TCP segment size.
_INIT_IP_ID = 0
_HTTP_PORT_NUM = 80  # 80 for http, 443 for https.
_TCP_PROTOCOL_ID = 6  # TCP protocol ID in IP header.
_DEFAULT_ADV_WINDOW = 5840
_DEFAULT_TTL = 255


class FilterRejectException(Exception):
    """
    Raised when received packet is not for raw HTTP GET.
    """
    pass


def checksum(msg):
    """
    Calculate checksum values for IP headers & TCP headers.
    Calculation logic is checked using the following example:
    "https://en.wikipedia.org/wiki/Internet_checksum#cite_note-7"
    
    Args:
        msg: A binary object used to calculate checksum, e.g. TCP header, IP header.
    Returns:
        A int that is a four-digit hex number, representing the checksum.
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
    Verify the IPv4 header checksum.
    Calculation logic is checked using the following example:
    "https://en.wikipedia.org/wiki/Internet_checksum#cite_note-7"

    Args:
        ip_header: A binary object representing an IP header.
    Returns:
        A boolean representing result of verification. True if correct; False otherwise.
    """
    iph = struct.unpack('!HHHHHHHHHH' , ip_header)
    checksum = sum(iph)
    while ip_check.bit_length() > 15:
        moving_digits = ip_check.bit_length() // 4 * 4
        carry_bit = ip_check >> moving_digits  # Find the first digit of the ip_check.
        ip_check = (ip_check & ((1 << moving_digits) - 1)) + carry_bit # Add the first digit to the rest.
    if ~ip_check & 0xFFFF != 0x0: # Flip all bits. Correct if result is 0x0000 = 0x0.
        return False
    else:
        return True


def ip_builder(ip_id, protocol, s_addr, d_addr):
    """
    Build & return a IP header for packets to be sent.
    
    Args:
        ip_id: An int representing the identification of this IP connection. Increase by 1 when a packet is sent.
        protocol: An int for protocol number. 6 as TCP.
        s_addr: A string of source IP address in dotted quad-string format.
        d_addr: A string of dest IP address in dotted quad-string format.
    Returns:
        A string of binary values as the IP header.
    """
    # IP header fields
    ip_ihl = 5
    ip_ver = 4
    ip_ihl_ver = (ip_ver << 4) + ip_ihl
    ip_tos = 0
    ip_tot_len = 0  # kernel will fill the correct total length
    ip_frag_off = 0
    ip_ttl = _DEFAULT_TTL
    ip_check = 0  # kernel will fill the correct checksum
    ip_saddr = socket.inet_aton(s_addr)
    ip_daddr = socket.inet_aton(d_addr)

    # the ! in the pack format string means network order
    return struct.pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, 
    ip_id, ip_frag_off, ip_ttl, protocol, ip_check, ip_saddr, ip_daddr)

def tcp_builder(s_addr, d_addr, s_port, d_port, tcp_seq_num, tcp_ack_num,
                fin, syn, rst, psh, ack, urg, window_size, usr_data):
    """
    Build & return a TCP header for packets to be sent, including packets for 3-way handshakes and ACK packets after that.

    Args:
        s_addr: A string of source IP address in dotted quad-string format.
        d_addr: A string of dest IP address in dotted quad-string format.
        s_port: An int representing the source end port number. The local port number listened by the sender. e.g. 1234
        d_port: An int representing the destination end port number. The remote port number listened by the receiver. e.g. 80 for http traffic.
        seq_num: An int representing the sequence number in current packet. Calculated using the ACK number of last packet received.
        ack_num: An int representing the ACK number in current packet. Calculated using seq_num of last packet ACKed + 1.
        fin: A binary int representing the FIN flag. 1 if FIN flag == 1;
        syn: A binary int representing the SYN flag. 1 if SYN flag == 1;
        ack: A binary int representing the ACK flag. 1 if ACK flag == 1;
        window_size: An int representing the advertised window size of the sender/client.
        usr_data:
    Returns:
        A string of binary values as the TCP header.
    """
    # TCP header fields
    tcp_doff = 5 # Data offset or size of tcp header in terms of 4-bytes words
    tcp_window = socket.htons(window_size)
    tcp_checksum = 0 # use checksum function to calculate it later
    tcp_urg_ptr = 0

    tcp_offset_res = (tcp_doff << 4) + 0 # 0 is for NS flag. Use 1 if NS flag is 1.
    tcp_flags = (fin + (syn << 1) + (rst << 2) + (psh <<3)
    + (ack << 4) + (urg << 5)) # note that TCP flags are in reverse order

    # the ! in the pack format string means network order
    tcp_header = struct.pack('!HHLLBBHHH' , s_port, d_port, tcp_seq_num, tcp_ack_num, tcp_offset_res, tcp_flags,  tcp_window, tcp_check, tcp_urg_ptr)

    # pseudo IP header fields for checksum calculation
    source_address = socket.inet_aton(s_addr)
    dest_address = socket.inet_aton(d_addr)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header) + len(usr_data)

    pih = struct.pack('!4s4sBBH', source_address, dest_address, placeholder, protocol, tcp_length)
    pih = pih + tcp_header + usr_data

    tcp_checksum = checksum(pih)

    # Makes the tcp header again and fill the correct checksum.
    # Notes that checksum is NOT in network byte order.
    tcp_header = (struct.pack('!HHLLBBH' , s_port, d_port, tcp_seq_num, 
    tcp_ack_num, tcp_offset_res, tcp_flags, tcp_window)
    + struct.pack('H', tcp_checksum) + struct.pack('!H' , tcp_urg_ptr))

    return tcp_header


def unpack_pckt_ip(pckt):
    """
    Unpacks an bytes object representing data received from the socket.
    Return a list of TCP header details. Raises a FilterRejectException if 
    non-TCP protocol is detected.
    
    Args:
        pckt: A bytes object representing data packet received.
    Returns:
        A tuple that contains IP header items.
    """
    # Unpacks the first 20 bytes for the IP header.
    ip_header = pckt[0:20]
    iph = struct.unpack('!BBHHHBBH4s4s' , ip_header)
    # items in iph:
    # 0 is version & IHL; 1 is DSCP & ECN; 2 is total length; 3 is IP id; 4 is flags & frag-offset;
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

    return (version, ihl, iph_length, id, ttl, protocol, s_addr, d_addr)


def unpack_pckt_tcp(pckt_no_ip):
    """
    Unpacks TCP header of an bytes object.
    Defensively unpacks a data packet to retrieve the TCP header information. 

    Args:
        pckt_no_ip: A bytes object of data packet after truncating IP header.
    Returns:
        A tuple that contains all TCP header items.
    """
    # Unpacks the 20 bytes after IP header for the TCP header.
    tcp_header = pckt_no_ip[0:20]
    tcph = struct.unpack('!HHLLBBHHH' , tcp_header)
    # items in tcph:
    # 0 is source port; 1 is dest port; 2 is seq num; 3 is ack num; 4 is offset;
    # 5 is reserved & NS flag; 6 is flags without NS; 7 is advertised window size;
    # 8 is checksum; 9 is urgent pointer;
    
    source_port = tcph[0]
    dest_port = tcph[1]
    sequence = tcph[2]
    acknowledgement = tcph[3]
    doff_reserved = tcph[4]
    tcph_length = doff_reserved >> 4
    tcph_length *= 4  # Use same unit as the iph_length in IP header.
    reserved_flags = tcph[5]
    fin = reserved_flags & (1)
    syn = (reserved_flags >> 1) & 1
    rst = (reserved_flags >> 2) & 1
    psh = (reserved_flags >> 3) & 1
    ack = (reserved_flags >> 4) & 1
    urg = (reserved_flags >> 5) & 1
    adv_window = tcph[6]
    checksum = tcph[7]

    return (source_port, dest_port, sequence, acknowledgement, tcph_length,
    fin, syn, rst, psh, ack, urg, adv_window, checksum)


def unpack_raw_http(pckt, remote_hostname, local_addr, local_port_num):
    """
    Unpacks an bytes object representing HTTP data received from raw socket.
    This should serve as a top-level receiver function that calls other helpers.

    Args:
        pckt: A binary object representing the packet with TCP & IP header.
        remote_hostname: A string representing the address of the remote server.
        local_addr: A string representing client local IP in dotted quad-string format.
        local_port_num: An int representing client local port number.
    Returns:
        A tuple of the packet without IP & TCP header and other parameters needed for connection.
    """
    # IP-level unpacking.
    (version, ihl, iph_length, ip_id, ttl, protocol,
    s_addr, d_addr) = unpack_pckt_ip(pckt)
    print("IP-level unpacking done!")

    # IP-level filter for packets for this app.
    if (s_addr != socket.gethostbyname(remote_hostname)
    or d_addr != local_addr):
        print("Exception: packet filtered.", s_addr, d_addr)
        raise FilterRejectException
    print("IP-level filtering done!")

    # TCP-level unpacking.
    (source_port, dest_port, sequence, acknowledgement, tcph_length,
    fin, syn, rst, psh, ack, urg,
    adv_window, checksum) = unpack_pckt_tcp(pckt[iph_length:])
    print("TCP-level unpacking done!")

    # TCP-level filter for packets for this app.
    if local_port_num != dest_port:
        print("Exception: packet filtered.")
        raise FilterRejectException
    print("TCP-level filtering done!")

    # TODO: Add TCP checksum validation?

    return (pckt[(iph_length + tcph_length):], sequence, acknowledgement,
    fin, syn, rst, psh, ack, urg, adv_window)


def pack_raw_http(s_addr, d_addr, s_port, ip_id, tcp_seq_num, tcp_ack_num,
                tcp_fin, tcp_syn, tcp_rst, tcp_psh, tcp_ack, tcp_urg, adv_window, data):
    """
    Pack http packets to send to server.
    
    Returns:
        A tuple that contains:
            A binary object as a http packet.
            A int as the id for next IP header to send.
    """
    data = data.encode()
    tcp_header = tcp_builder(s_addr, d_addr, s_port, _HTTP_PORT_NUM, 
    tcp_seq_num, tcp_ack_num, tcp_fin, tcp_syn, tcp_rst, tcp_psh, tcp_ack, 
    tcp_urg, adv_window, data)
    ip_header = ip_builder(ip_id, _TCP_PROTOCOL_ID, s_addr, d_addr)
    print("====================")
    print(ip_header.hex())
    print(tcp_header.hex())
    print(data.hex())
    print("====================")

    # Sequentially increments the IP identifier.
    # IP id for next IP header to send.
    return (ip_header + tcp_header + data, ip_id + 1)


def tear_down_tcp(sends, recvs, remote_hostname, ip_id):
    """
    
    """
    # http_data = http_data.decode(encoding="utf-8")
    # http_data_list = http_data.split("\r\n\r\n")
    # if len(http_data_list) == 2:
    #     http_header = http_data_list[0]
    #     http_body = http_data_list[1]
    #     # header_list = http_header.split("\r\n")
    # else:
    #     print("Error in getting http header and data body")

    # full_http_data = ''

    # return full_http_data
    pass


def set_up_tcp(sends, recvs, s_addr, remote_hostname,
                ip_id, tcp_sender_seq, tcp_receiver_seq):
    """
    Communicate with server by 3-way handshake.
    Args:
    Returns:
        A tuple that contains:
            An int for server's next ACK number
            An int for server's next sequence number
            An int for server's next IP header id
    """
    # Method to get local host name
    d_addr = socket.gethostbyname(remote_hostname)
    s_port = sends.getsockname()[1]
    adv_window = _DEFAULT_ADV_WINDOW

    # Sends SYN packet.
    data = ""
    fin = rst = psh = ack = urg = 0
    syn = 1
    (packet, ip_id) = pack_raw_http(s_addr, d_addr, s_port, ip_id,
    tcp_sender_seq, tcp_receiver_seq, fin, syn, rst, psh, ack, urg, adv_window, 
    data)
    try:
        bytes_sent = sends.sendto(packet, (d_addr, 0))
        print(str(bytes_sent))
        print("Bytes sent!")
        print(s_addr, d_addr)
    except:
        print("Error: Failed to send 1st SYN packet in the 3-way handshake.")
        sends.close()

    # Waits for SYN/ACK from server.
    while True:
        packet, _ = recvs.recvfrom(_BUFFER_SIZE)
        try:
        # Note the exchange of sender and receiver seq num positions.
        # tcp_sender_seq: next packet seq num
        # tcp_receiver_seq + 1: next packet ACK num
        (_, tcp_receiver_seq, tcp_sender_seq, fin, syn, rst, psh, ack, urg, adv_window) = unpack_raw_http(packet, remote_hostname,
            s_addr, s_port)

        if syn == ack == True and fin == rst == psh == urg == False:
            print("Received valid SYN/ACK")
        else:
            print("Error: SYN/ACK invalid!")
            break
    # Checks if the packet is intended for other processes.
    except FilterRejectException:
        pass
    # Checks if a packet intended for our app is illegal.
    # TODO: Add such checks.
    except Exception as e:
        print("Error: Illegal response received!")
        print(e)
    
    # Sends the last ACK to complete three-way handshake.
    data = ""
    fin = syn = rst = psh = urg = 0
    ack = 1
    # tcp_receiver_seq + 1: next packet ACK num
    tcp_receiver_seq += 1
    (packet, ip_id) = pack_raw_http(s_addr, d_addr, s_port, ip_id,
    tcp_sender_seq, tcp_receiver_seq, fin, syn, rst, psh, ack, urg, 
    min(adv_window, _DEFAULT_ADV_WINDOW), data)
    # min(adv_window, _DEFAULT_ADV_WINDOW)
    # print("Packet:", packet.hex())
    try:
        bytes_sent = sends.send(packet)
        # bytes_sent = sends.sendto(packet, (d_addr, 0))
        print(str(bytes_sent))
        print("Bytes sent!")
    except:
        print("Error: Failed to send last SYN packet in the 3-way handshake.")
        sends.close()

    # TODO: Check the validity of sequence numbers here.
    # next packet to send should have:
    # tcp_receiver_seq as seq num
    # tcp_sender_seq + 1 as ACK num
    return (tcp_sender_seq + 1, tcp_receiver_seq, ip_id)


def raw_http_get(sends, recvs, remote_hostname,
                    tcp_sender_seq, tcp_receiver_seq, ip_id):
    """
    
    """
    counter = 1  # DEBUG
    while True:
        packet, addr = recvs.recvfrom(_BUFFER_SIZE)
        
        # TODO: How to ensure complete packets are received?
        # This seems no guaranteed for TCP, but the tutorial seems to assume it anyway.
        # https://stackoverflow.com/questions/67509709/is-recvbufsize-guaranteed-to-receive-all-the-data-if-sended-data-is-smaller-th

        try:
            filter_flag, ip_header_list, pckt_no_ip = unpack_raw_http(packet, remote_hostname, sends.getsockname()[1])

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

            # Gets the IP address of local machine.
            try:
                send_s.connect((socket.gethostbyname(url_hostname), 0))
                s_addr = send_s.getsockname()[0]
            except Exception as e:
                s_addr = '127.0.0.1'
            # s_addr = '192.168.1.240' # Hard-code
            # s_addr = '10.0.0.98' # Hard-code


            # Randomly picks the first seq num.
            tcp_sender_seq = random.randint(0, 2**31)
            # SYN packet is the first packet in this connection.
            tcp_receiver_seq = 0

            
            (tcp_sender_seq, tcp_receiver_seq, ip_id) = set_up_tcp(send_s, 
            recv_s, s_addr, url_hostname,
            _INIT_IP_ID, tcp_sender_seq, tcp_receiver_seq)


            (raw_http_get_res, tcp_sender_seq, tcp_receiver_seq,
            ip_id) = raw_http_get(send_s, recv_s, url_hostname,
            tcp_sender_seq, tcp_receiver_seq, ip_id)

            # TODO: Convert 'raw_http_get_res' into HTML and save it.

            tear_down_tcp(send_s, recv_s, url_hostname,
                            tcp_sender_seq, tcp_receiver_seq, ip_id)

            # tear_down_tcp(send_s, recv_s, url_hostname, tcp_sender_seq, tcp_receiver_seq, ip_id)

            # # 1st SYN packet from local host. Use _TEST_URL for test purpose.
            # data = "".encode(encoding="utf-8")
            # # "10.0.0.98" is local IP address got by Wireshark. Somehow this is different than get method result
            # tcp_header = tcp_builder(2104, 80, True, False, _TCP_SEQ_NUM, 0, 5840, "10.0.0.98", socket.gethostbyname(url_hostname), data)
            # # print("TCP header:", tcp_header)
            # ip_header = ip_builder(_IP_ID, socket.IPPROTO_TCP, "10.0.0.98", socket.gethostbyname(url_hostname))
            # # print("IP header:", ip_header)
            # packet = ip_header + tcp_header + data
            # # SYN sent successfully
            # try:
            #     send_s.sendto(packet, (socket.gethostbyname(url_hostname), 0))
            #     print("Send 1st SYN packet successfully!")
            # except:
            #     print("Error: Failed to send 1st SYN packet in the 3-way handshake.")
    
            # # Receive SYN/ACK packet
            # try:
            #     (packet, addr) = recv_s.recvfrom(_BUFFER_SIZE)
            #     (ip_header_tuple, tcp_header_tuple, http_pckt) = unpack_raw_http(packet, socket.gethostbyname(url_hostname), "10.0.0.98")
            #     # TCP sequence number, TCP acknowledge number, TCP ACK flag, TCP SYN flag
            #     (tcp_header_tuple[1], tcp_header_tuple[2], tcp_header_tuple[5], tcp_header_tuple[6], http_pckt)
            #     print(ip_header_tuple, tcp_header_tuple, http_pckt)

            # # (sequence, acknowledge, ack_flag, syn_flag) = raw_http_get(sends, recvs, remote_hostname)
            # except:
            #     print("Error: Failed to receive 1st SYN/ACK packet in the 3-way handshake.")
            # # SYN/ACK received successfully
            
            # data = "".encode(encoding="utf-8")
            # tcp_header = tcp_builder(2104, 80, False, True, _TCP_SEQ_NUM, tcp_header_tuple[1] + 1, 513, "10.0.0.98", socket.gethostbyname(url_hostname), data)
            # ip_header = ip_builder(_IP_ID, socket.IPPROTO_TCP, "10.0.0.98", socket.gethostbyname(url_hostname))
            # packet = ip_header + tcp_header + data
            # try:
            #     send_s.sendto(packet, (socket.gethostbyname(url_hostname), 0))
            #     print("Send 2nd ACK packet successfully!")
            # except:
            #     print("Error: Failed to send 2nd ACK packet in the 3-way handshake.")
            #     send_s.close()

            # # 2nd ACK packet from local host.

            # # (ip_header_tuple, tcp_header_tuple, http_pckt) = unpack_raw_http(packet, remote_hostname, sends.getsockname()[1])
            # # (tcp_header_tuple[1], tcp_header_tuple[2], tcp_header_tuple[5], tcp_header_tuple[6], http_pckt)

            # # (sequence, acknowledge, ack_flag, syn_flag) = raw_http_get(sends, recvs, remote_hostname)
            # # if (acknowledge == _TCP_SEQ_NUM + 1 and ack_flag == True and syn_flag == True):
            #     # print("Receive 1st SYN/ACK packet successfully!")
            # # else:
            #     # print("Error: Failed to receive 1st SYN/ACK packet in the 3-way handshake.")
    
    return


if __name__ == "__main__":
    main()