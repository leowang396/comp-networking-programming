"""
Project 3: Raw Sockets
"""
import random
import sys
import socket
import struct
import time
from urllib.parse import urlparse

_TEST_URL = "http://david.choffnes.com/classes/cs5700f22/2MB.log"
_BUFFER_SIZE = 65565  # Max possible TCP segment size.
_INIT_IP_ID = 0
_HTTP_PORT_NUM = 80  # 80 for http, 443 for https.
_TCP_PROTOCOL_ID = 6  # TCP protocol ID in IP header.
_DEFAULT_ADV_WINDOW = 5840
_DEFAULT_TTL = 255


# TODO: TCP 1-min time out.


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
        w = msg[i]
        # If a segment contains an odd number of header and text octets to be 
        # checksummed, the last octet is padded on the right with zeros to form 
        # a 16 bit word for checksum purposes.
        if (i + 1) < len(msg):
            w += (msg[i+1] << 8)
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


def build_ip_head(ip_id, protocol, s_addr, d_addr):
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
    ip_ihl = 5
    ip_ver = 4
    ip_ihl_ver = (ip_ver << 4) + ip_ihl
    ip_tos = 0
    # TODO: Kernel does not seem to be filling tot_len and checksum.
    ip_tot_len = 0  # kernel will fill the correct total length
    ip_frag_off = 0
    ip_ttl = _DEFAULT_TTL
    ip_check = 0  # kernel will fill the correct checksum
    ip_saddr = socket.inet_aton(s_addr)
    ip_daddr = socket.inet_aton(d_addr)

    return struct.pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, 
    ip_id, ip_frag_off, ip_ttl, protocol, ip_check, ip_saddr, ip_daddr)


def build_tcp_head(s_addr, d_addr, s_port, d_port, tcp_seq_num, tcp_ack_num,
 fin, syn, rst, psh, ack, urg, window_size, usr_data):
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
    tcp_doff = 5  # Data offset or size of tcp header in terms of 4-bytes words
    tcp_window = socket.htons(window_size)
    tcp_check = 0
    tcp_urg_ptr = 0

    tcp_offset_res = (tcp_doff << 4) + 0
    tcp_flags = (fin + (syn << 1) + (rst << 2) + (psh <<3)
    + (ack << 4) + (urg << 5))

    tcp_header = struct.pack('!HHLLBBHHH' , s_port, d_port, tcp_seq_num, tcp_ack_num, tcp_offset_res, tcp_flags,  tcp_window, tcp_check, tcp_urg_ptr)

    # pseudo IP header fields for checksum calculation
    source_address = socket.inet_aton(s_addr)
    dest_address = socket.inet_aton(d_addr)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header) + len(usr_data)

    psh = struct.pack('!4s4sBBH', source_address, dest_address, placeholder, 
    protocol, tcp_length)
    psh = psh + tcp_header + usr_data

    tcp_checksum = checksum(psh)

    # Makes the tcp header again and fill the correct checksum - remember
    # checksum is NOT in network byte order.
    tcp_header = (struct.pack('!HHLLBBH' , s_port, d_port, tcp_seq_num, 
    tcp_ack_num, tcp_offset_res, tcp_flags, tcp_window)
    + struct.pack('H', tcp_checksum) + struct.pack('!H' , tcp_urg_ptr))

    return tcp_header


def unpack_ip_head(pckt):
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

    # TODO: Add IP checksum verification.

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


def unpack_tcp_head(pckt_no_ip):
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
    """Unpacks an bytes object representing HTTP data received from raw socket.
    
    This should serve as a top-level receiver function that calls other helpers.
    """
    # IP-level unpacking.
    (version, ihl, iph_length, ip_id, ttl, protocol,
    s_addr, d_addr) = unpack_ip_head(pckt)
    # print("IP-level unpacking done!")

    # IP-level filter for packets for this app.
    if (s_addr != socket.gethostbyname(remote_hostname)
    or d_addr != local_addr):
        raise FilterRejectException
    print("IP-level filtering done!")

    # TCP-level unpacking.
    (source_port, dest_port, sequence, acknowledgement, tcph_length,
    fin, syn, rst, psh, ack, urg,
    adv_window, checksum) = unpack_tcp_head(pckt[iph_length:])
    print("TCP-level unpacking done!")

    # TCP-level filter for packets for this app.
    if local_port_num != dest_port:
        raise FilterRejectException
    print("TCP-level filtering done!")

    # TODO: Add TCP checksum validation.

    return (pckt[(iph_length + tcph_length):], sequence, acknowledgement,
    fin, syn, rst, psh, ack, urg, adv_window)


def pack_raw_http(s_addr, d_addr, s_port, ip_id, tcp_seq_num, tcp_ack_num,
    tcp_fin, tcp_syn, tcp_rst, tcp_psh, tcp_ack, tcp_urg, adv_window, data):
    ip_header = build_ip_head(ip_id, _TCP_PROTOCOL_ID, s_addr, d_addr)

    data = data.encode()
    tcp_header = build_tcp_head(s_addr, d_addr, s_port, _HTTP_PORT_NUM, 
    tcp_seq_num, tcp_ack_num, tcp_fin, tcp_syn, tcp_rst, tcp_psh, tcp_ack, 
    tcp_urg, adv_window, data)
    print("====================")
    ip_hex = str(ip_header.hex())
    ip_hex = " ".join([ip_hex[i:i+2] for i in range(0, len(ip_hex), 2)])
    print("IP Header:\t" + ip_hex)
    tcp_hex = str(tcp_header.hex())
    tcp_hex = " ".join([tcp_hex[i:i+2] for i in range(0, len(tcp_hex), 2)])
    print("TCP Header:\t" + tcp_hex)
    data_hex = str(data.hex())
    data_hex = " ".join([data_hex[i:i+2] for i in range(0, len(data_hex), 2)])
    print("Data Payload:\t" + data_hex)
    print("====================")

    # Sequentially increments the IP identifier.
    ip_id = (ip_id + 1) % (2**16)
    return (ip_header + tcp_header + data, ip_id)


def tear_down_tcp(sends, recvs, parsed_url, s_addr,
tcp_sender_seq, tcp_receiver_seq, ip_id, adv_window):
    d_addr = socket.gethostbyname(parsed_url.hostname)
    s_port = sends.getsockname()[1]

    # Sends the last FIN/ACK packet.
    syn = rst = psh = urg = 0
    fin = ack = 1
    adv_window = min(adv_window, _DEFAULT_ADV_WINDOW)
    data = ""
    (packet, ip_id) = pack_raw_http(s_addr, d_addr, s_port, ip_id,
    tcp_sender_seq, tcp_receiver_seq, fin, syn, rst, psh, ack, urg, 
    adv_window, data)
    try:
        n = sends.sendto(packet, (d_addr, 0))

        print(f"{n} bytes sent!")
    except:
        print("Error: Failed to send the last FIN/ACK packet.")
        sends.close()

    # Waits for the last ACK from server.
    while True:
        recvs.settimeout(180)
        try:
            packet, _ = recvs.recvfrom(_BUFFER_SIZE)
            (_, tcp_receiver_seq, tcp_sender_seq,
            fin, syn, rst, psh, ack, urg, adv_window) = unpack_raw_http(packet, 
            parsed_url.hostname, s_addr, s_port)

            if ack == True and fin == syn == rst == psh == urg == False:
                print("Received valid ACK")
            else:
                raise ValueError("Invalid ACK response!")
            break
        except TimeoutError:
            print("Error: No data received in 3 mins.")
            exit(1)
        # Checks if the packet is intended for other processes.
        except FilterRejectException:
            pass
        # Checks if a packet intended for our app is illegal.
        except Exception as e:
            print("Error: Illegal response received!")
            print(repr(e))

    return


def set_up_tcp(sends, recvs, s_addr, remote_hostname,
ip_id, tcp_sender_seq, tcp_receiver_seq):
    d_addr = socket.gethostbyname(remote_hostname)
    s_port = sends.getsockname()[1]

    # Sends the 1st SYN packet.
    data = ""
    fin = rst = psh = ack = urg = 0
    syn = 1
    (packet, ip_id) = pack_raw_http(s_addr, d_addr, s_port, ip_id,
    tcp_sender_seq, tcp_receiver_seq, fin, syn, rst, psh, ack, urg, 
    _DEFAULT_ADV_WINDOW, data)
    try:
        n = sends.sendto(packet, (d_addr, 0))

        print(f"{n} bytes sent!")
    except:
        print("Error: Failed to send 1st SYN packet in the 3-way handshake.")
        sends.close()

    # Waits for SYN/ACK from server.
    while True:
        recvs.settimeout(180)
        try:
            packet, _ = recvs.recvfrom(_BUFFER_SIZE)
            (_, tcp_receiver_seq, tcp_sender_seq,
            fin, syn, rst, psh, ack, urg, adv_window) = unpack_raw_http(packet, 
            remote_hostname, s_addr, s_port)

            # print(fin)  # DEBUG
            # print(syn) 
            # print(rst)
            # print(psh)
            # print(ack)
            # print(urg)

            if syn == ack == True and fin == rst == psh == urg == False:
                print("Received valid SYN/ACK")
            else:
                raise ValueError("Invalid SYN/ACK response!")
            break
        # Checks if the packet is intended for other processes.
        except FilterRejectException:
            pass
        except TimeoutError:
            print("Error: No data received in 3 mins.")
            exit(1)
        # Checks if a packet intended for our app is illegal.
        except Exception as e:
            print("Error: Illegal response received!")
            print(repr(e))
    
    # Sends the last ACK to complete three-way handshake.
    data = ""
    fin = syn = rst = psh = urg = 0
    ack = 1
    tcp_receiver_seq += 1
    adv_window = min(adv_window, _DEFAULT_ADV_WINDOW)
    (packet, ip_id) = pack_raw_http(s_addr, d_addr, s_port, ip_id,
    tcp_sender_seq, tcp_receiver_seq, fin, syn, rst, psh, ack, urg, 
    adv_window, data)
    try:
        n = sends.sendto(packet, (d_addr, 0))

        print(f"{n} bytes sent!")
    except:
        print("Error: Failed to send last SYN packet in the 3-way handshake.")
        sends.close()

    return (tcp_sender_seq, tcp_receiver_seq, ip_id, adv_window)


def raw_http_get(sends, recvs, parsed_url, s_addr,
tcp_sender_seq, tcp_receiver_seq, ip_id, adv_window):
    d_addr = socket.gethostbyname(parsed_url.hostname)
    s_port = sends.getsockname()[1]
    data = "".join(["GET ", parsed_url.path, " HTTP/1.1", "\r\n",
    "Host: ", parsed_url.hostname, "\r\n\r\n"])

    fin = syn = rst = urg = 0
    psh = ack = 1
    (packet, ip_id) = pack_raw_http(s_addr, d_addr, s_port, ip_id, 
    tcp_sender_seq, tcp_receiver_seq, fin, syn, rst, psh, ack, urg,
    adv_window, data)

    try:
        n = sends.sendto(packet, (d_addr, 0))

        print(f"{n} bytes sent!")
    except Exception as e:
        print("Error: Failed to send GET request.")
        print(e)
        sends.close()

    # Uses TCP connection to receive the HTML file, until FIN response.
    counter = 1  # DEBUG
    html_doc = b""
    recvs.settimeout(180)
    while True:
        try:
            # TODO: Add TCP congestion window.
            packet, _ = recvs.recvfrom(_BUFFER_SIZE)
            # Receives a HTTP GET response packet.
            (res, seq_num, tcp_sender_seq,
            fin, syn, rst, psh, ack, urg, adv_window) = unpack_raw_http(packet, 
            parsed_url.hostname, s_addr, sends.getsockname()[1])

            # print(fin)  # DEBUG
            # print(syn) 
            # print(rst)
            # print(psh)
            # print(ack)
            # print(urg)

            if fin == ack == 1 and syn == rst == urg == psh == 0:
                print("FIN/ACK packet received!")
                break
            elif fin == ack == psh == 1 and syn == rst == urg == 0:
                print("FIN/ACK/PSH packet received!")

                # Checks for out-of-order or duplicate packets.
                print("tcp_receiver_seq: " + str(tcp_receiver_seq))
                print("len(res): " + str(len(res)))
                print("seq_num: " + str(seq_num))
                if tcp_receiver_seq != seq_num and tcp_receiver_seq != seq_num + 1:
                    raise ValueError("Out of order! Packet discarded.")
                else:
                    tcp_receiver_seq = seq_num

                print("Packet #" + str(counter) + ":")  # DEBUG
                counter += 1
                html_doc += res
                print(res)

                break

            # Checks for out-of-order or duplicate packets.
            print("tcp_receiver_seq: " + str(tcp_receiver_seq))
            print("len(res): " + str(len(res)))
            print("seq_num: " + str(seq_num))
            if tcp_receiver_seq != seq_num and tcp_receiver_seq != seq_num + 1:
                raise ValueError("Out of order! Packet discarded.")
            else:
                tcp_receiver_seq = seq_num

            print("Packet #" + str(counter) + ":")  # DEBUG
            counter += 1
            html_doc += res
            print(res)

            # ACKs a received packet.
            tcp_receiver_seq += len(res)
            fin = syn = rst = psh = urg = 0
            ack = 1
            adv_window = min(adv_window, _DEFAULT_ADV_WINDOW)
            data = ""
            (packet, ip_id) = pack_raw_http(s_addr, d_addr, s_port, ip_id, 
            tcp_sender_seq, tcp_receiver_seq, fin, syn, rst, psh, ack, urg,
            adv_window, data)
            try:
                n = sends.sendto(packet, (d_addr, 0))

                print(f"{n} bytes sent!")
            except Exception as e:
                print("Error: Failed to send ACK.")
                print(e)
                sends.close()

        except TimeoutError:
            print("Error: No data received in 3 mins.")
            exit(1)
        # Checks if the packet is intended for other processes.
        except FilterRejectException:
            pass
        # Checks if a packet intended for our app is illegal.
        except Exception as e:
            print("Error: Illegal response received!")
            print(e)

    head_content_split = html_doc.split(b"\r\n\r\n", 1)

    if head_content_split[0].split(b" ")[1] != b"200":
        print("Error: non-200 status code encounterd.")
        exit(1)
    
    return (head_content_split[1], tcp_sender_seq, tcp_receiver_seq, ip_id)


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

            # Gets the local IP address.
            try:
                send_s.connect((socket.gethostbyname(url_hostname), 0))
            except Exception as e:
                print(e)
            s_addr = send_s.getsockname()[0]

            # Randomly picks the first seq num.
            # random seed?
            # use it for the port num as well
            tcp_sender_seq = random.randint(0, 2**31)
            # SYN packet is the first packet in this connection.
            tcp_receiver_seq = 0

            (tcp_sender_seq, tcp_receiver_seq,
            ip_id, adv_window) = set_up_tcp(send_s, recv_s, s_addr, 
            url_hostname, _INIT_IP_ID, tcp_sender_seq, tcp_receiver_seq)

            (raw_http_get_res, tcp_sender_seq, tcp_receiver_seq,
            ip_id) = raw_http_get(send_s, recv_s, parsed_url, s_addr,
            tcp_sender_seq, tcp_receiver_seq, ip_id, adv_window)

            tear_down_tcp(send_s, recv_s, parsed_url, s_addr,
            tcp_sender_seq, tcp_receiver_seq, ip_id, adv_window)

            file_name = parsed_url.path.split("/")[-1]
            file_name = file_name if file_name else "index.html"
            with open(file_name, "wb") as file:
                file.write(raw_http_get_res)

    return


if __name__ == "__main__":
    main()