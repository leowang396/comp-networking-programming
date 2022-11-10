#! /usr/bin/env python3

"""
Project 3: Raw Sockets
"""
import random
import sys
import socket
import struct
from urllib.parse import urlparse


_TEST_URL = "http://david.choffnes.com/classes/cs5700f22/2MB.log"
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
    Calculate checksum required in IP headers & TCP headers.

    Args:
        msg: A bytes object used to calculate the checksum.
    Returns:
        A four digit hex number representing the checksum calculated.
    """
    s = 0

    # Take 2 characters at a time.
    for i in range(0, len(msg), 2):
        # No need for ord() in python 3.
        w = msg[i]
        # If a segment contains an odd number of header and text octets to be 
        # checksummed, the last octet is padded on the right with zeros to form 
        # a 16 bit word for checksum purposes.
        if (i + 1) < len(msg):
            w += (msg[i+1] << 8)
        s = s + w
    
    s = (s >> 16) + (s & 0xffff)
    s = s + (s >> 16)
    
    # Take complement and mask to 4 byte short.
    s = ~s & 0xffff
    
    return s


def build_ip_head(ip_id, protocol, s_addr, d_addr, ip_tot_len):
    """
    Build & return a IP header for packets to be sent, including packets for handshakes and packets after that.

    Args:
        ip_id: An int representing the identification of this IP connection.
        protocol: An int for protocol number. 6 as TCP.
        s_addr: A string of source IP address in dotted quad-string format.
        d_addr: A string of dest IP address in dotted quad-string format.
        ip_tot_len: An int for length of data other than IP header part. Minimum 20.
    Returns:
        A string of binary values as the IP header.
    """
    ip_ihl = 5
    ip_ver = 4
    ip_ihl_ver = (ip_ver << 4) + ip_ihl
    ip_tos = 0
    ip_frag_off = 0
    ip_ttl = _DEFAULT_TTL
    ip_checksum = 0
    ip_saddr = socket.inet_aton(s_addr)
    ip_daddr = socket.inet_aton(d_addr)

    # Calculate checksum and pack again.
    ip_header = struct.pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, 
    ip_id, ip_frag_off, ip_ttl, protocol, ip_checksum, ip_saddr, ip_daddr)
    ip_checksum = checksum(ip_header)
    ip_header = struct.pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, 
    ip_id, ip_frag_off, ip_ttl, protocol, ip_checksum, ip_saddr, ip_daddr)
    
    return ip_header


def build_tcp_head(s_addr, d_addr, s_port, d_port, tcp_seq_num, tcp_ack_num,
fin, syn, rst, psh, ack, urg, window_size, usr_data):
    """
    Build & return a TCP header for packets to be sent, including packets for handshakes and packets after that.

    Args:
        s_addr: A string of source IP address in dotted quad-string format.
        d_addr: A string of dest IP address in dotted quad-string format.
        s_port: An int representing the source end port number. The local port number listened by the sender. e.g. 1234
        d_port: An int representing the destination end port number. The remote port number listened by the receiver. e.g. 80 for http traffic.
        tcp_seq_num: An int representing the sequence number in current packet.
        tcp_ack_num: An int representing the ACK number in current packet.
        fin: A binary int number representing the FIN flag. 1 if FIN flag == 1; 0 otherwise.
        syn: A binary int number representing the SYN flag. 1 if SYN flag == 1; 0 otherwise.
        rst: A binary int number representing the RST flag. 1 if RST flag == 1; 0 otherwise.
        psh: A binary int number representing the PSH flag. 1 if PSH flag == 1; 0 otherwise.
        ack: A binary int number representing the ACK flag. 1 if ACK flag == 1; 0 otherwise.
        urg: A binary int number representing the URG flag. 1 if URG flag == 1; 0 otherwise.
        window_size: A int representing the advertised window size of client. Maximum is 5840.
        usr_data: A bytes object representing the data used in TCP data body.
    Returns:
        A string of binary values as the TCP header.
    """
    tcp_doff = 5 # Data offset or size of tcp header in terms of 4-bytes words.
    tcp_window = socket.htons(window_size)
    tcp_check = 0
    tcp_urg_ptr = 0

    tcp_offset_res = (tcp_doff << 4) + 0
    tcp_flags = (fin + (syn << 1) + (rst << 2) + (psh <<3)
    + (ack << 4) + (urg << 5))

    tcp_header = struct.pack('!HHLLBBHHH' , s_port, d_port, tcp_seq_num, tcp_ack_num, tcp_offset_res, tcp_flags,  tcp_window, tcp_check, tcp_urg_ptr)

    # Pseudo IP header fields for checksum calculation.
    source_address = socket.inet_aton(s_addr)
    dest_address = socket.inet_aton(d_addr)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header) + len(usr_data)

    psh = struct.pack('!4s4sBBH', source_address, dest_address, placeholder, 
    protocol, tcp_length)
    psh = psh + tcp_header + usr_data

    tcp_checksum = checksum(psh)

    # Make the tcp header again and fill the correct checksum.
    # Checksum is NOT in network byte order.
    tcp_header = (struct.pack('!HHLLBBH' , s_port, d_port, tcp_seq_num, 
    tcp_ack_num, tcp_offset_res, tcp_flags, tcp_window)
    + struct.pack('H', tcp_checksum) + struct.pack('!H' , tcp_urg_ptr))

    return tcp_header


def unpack_ip_head(pckt):
    """
    Unpack a bytes object representing data received from the socket.
    Return a tuple of TCP header items.
    Raise a FilterRejectException if non-TCP protocols are detected.

    Args:
        pckt: A bytes object representing data packet received.
    Returns:
        A tuple that contains TCP header items including:
            (version, ihl, iph_length, id, ttl, protocol, s_addr, d_addr)
    """
    # Unpack the first 20 bytes for the IP header.
    ip_header = pckt[0:20]
    iph = struct.unpack('!BBHHHBBH4s4s' , ip_header)
    # Items in iph: 0 is version & IHL; 1 is DSCP & ECN; 2 is total length; 3 is IP id;
    # 4 is flags & frag-offset; 5 is TTL; 6 is protocol; 7 is IP header checksum;
    # 8 is source IP address; 9 is dest IP address;

    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
    iph_length = ihl * 4  # Header length in bytes.

    id = iph[3]
    ttl = iph[5]
    protocol = iph[6]
    # Convert s_addr and d_addr to dotted quad-string format.
    s_addr = socket.inet_ntoa(iph[8])
    d_addr = socket.inet_ntoa(iph[9])

    # Filter out non-TCP packets.
    if protocol != _TCP_PROTOCOL_ID:
        raise FilterRejectException

    return (version, ihl, iph_length, id, ttl, protocol, s_addr, d_addr)


def unpack_tcp_head(pckt_no_ip):
    """
    Unpack the TCP header of a bytes object defensively.

    Args:
        pckt_no_ip: A bytes object of data packet after truncating the IP header.
    Returns:
        A tuple that contains TCP header items, including:
            (source_port, dest_port, sequence, acknowledgement, tcph_length, fin, syn, rst, psh, ack, urg, adv_window, checksum)
    """
    # Unpack the 20 bytes after IP header for the TCP header.
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
    """
    Unpack a bytes object representing HTTP data received from raw socket.
    This should serve as a top-level receiver function that calls other helpers.

    Args:
        pckt: A bytes object representing a raw packet with the IP header and the TCP header.
        remote_hostname: A string representing the remote server. e.g. david.choffnes.com
        local_addr: A string representing the IP address of local client in dotted quad-string format.
        local_port_num: An int representing the port number used by the local client.
    Returns:
        A tuple that contains HTTP data, TCP sequence number, TCP acknowledgement number, TCP flags and TCP advertised window size.
    """
    # IP-level unpacking.
    (version, ihl, iph_length, ip_id, ttl, protocol,
    s_addr, d_addr) = unpack_ip_head(pckt)
    # print("IP-level unpacking done!")

    # IP-level filter for packets received by this application.
    if (s_addr != socket.gethostbyname(remote_hostname)
    or d_addr != local_addr):
        raise FilterRejectException
    print("IP-level filtering done!")

    # TCP-level unpacking.
    (source_port, dest_port, sequence, acknowledgement, tcph_length,
    fin, syn, rst, psh, ack, urg,
    adv_window, checksum) = unpack_tcp_head(pckt[iph_length:])
    print("TCP-level unpacking done!")

    # TCP-level filter for packets received by this application.
    if local_port_num != dest_port:
        raise FilterRejectException
    print("TCP-level filtering done!")

    return (pckt[(iph_length + tcph_length):], sequence, acknowledgement,
    fin, syn, rst, psh, ack, urg, adv_window)


def pack_raw_http(s_addr, d_addr, s_port, ip_id, tcp_seq_num, tcp_ack_num,
    tcp_fin, tcp_syn, tcp_rst, tcp_psh, tcp_ack, tcp_urg, adv_window, data):
    """
    Pack raw packets for the client to send to server.

    Args:
        s_addr: A string of source IP address in dotted quad-string format.
        d_addr: A string of dest IP address in dotted quad-string format.
        s_port: An int representing the port number of the client.
        ip_id: An int representing the IP identifier for the raw packet.
        tcp_seq_num: An int representing the TCP sequence number for the raw packet.
        tcp_ack_num: An int representing the TCP acknowledge number for the raw packet.
        tcp_fin: A binary int number representing the TCP FIN flag. 1 if FIN flag == 1; 0 otherwise.
        tcp_syn: A binary int number representing the TCP SYN flag. 1 if SYN flag == 1; 0 otherwise.
        tcp_rst: A binary int number representing the TCP RST flag. 1 if RST flag == 1; 0 otherwise.
        tcp_psh: A binary int number representing the TCP PSH flag. 1 if PSH flag == 1; 0 otherwise.
        tcp_ack: A binary int number representing the TCP ACK flag. 1 if ACK flag == 1; 0 otherwise.
        tcp_urg: A binary int number representing the TCP URG flag. 1 if URG flag == 1; 0 otherwise.
        adv_window: An int representing the advertised window size for the client.
        data: A string that contains the data body to be sent in the raw packet.
    Returns:
        A tuple that contains the raw packet to be sent and the IP identifier.
    """
    data = data.encode()
    tcp_header = build_tcp_head(s_addr, d_addr, s_port, _HTTP_PORT_NUM, 
    tcp_seq_num, tcp_ack_num, tcp_fin, tcp_syn, tcp_rst, tcp_psh, tcp_ack, 
    tcp_urg, adv_window, data)

    ip_header = build_ip_head(ip_id, _TCP_PROTOCOL_ID, s_addr, d_addr, len(data + tcp_header))

    # Debug code
    # ip_hex = str(ip_header.hex())
    # ip_hex = " ".join([ip_hex[i:i+2] for i in range(0, len(ip_hex), 2)])

    # tcp_hex = str(tcp_header.hex())
    # tcp_hex = " ".join([tcp_hex[i:i+2] for i in range(0, len(tcp_hex), 2)])

    # data_hex = str(data.hex())
    # data_hex = " ".join([data_hex[i:i+2] for i in range(0, len(data_hex), 2)])

    # Increment the IP identifier sequentially.
    ip_id = (ip_id + 1) % (2**16)
    return (ip_header + tcp_header + data, ip_id)


def tear_down_tcp(sends, recvs, parsed_url, s_addr,
tcp_sender_seq, tcp_receiver_seq, ip_id, adv_window):
    """
    Send the last packet and shut down the connection to the server.

    Args:
        sends: A socket instance used to send data to the server.
        recvs: A socket instance used to receive data from the server.
        parsed_url: A string representing the URL domain name. It can be transformed into the server IP address.
        s_addr: A string representing the client IP address in dotted quad-string format.
        tcp_sender_seq: An int representing the TCP sequence initiated by the client.
        tcp_receiver_seq: An int representing the TCP sequence obtained from the server.
        ip_id: An int representing the IP identifier.
        adv_window: An int representing the advertised window size.
    """
    d_addr = socket.gethostbyname(parsed_url.hostname)
    s_port = sends.getsockname()[1]

    # Send the last FIN/ACK packet.
    syn = rst = psh = urg = 0
    fin = ack = 1
    adv_window = min(adv_window, _DEFAULT_ADV_WINDOW)
    data = ""
    (packet, ip_id) = pack_raw_http(s_addr, d_addr, s_port, ip_id,
    tcp_sender_seq, tcp_receiver_seq, fin, syn, rst, psh, ack, urg, 
    adv_window, data)
    try:
        n = sends.sendto(packet, (d_addr, 0))
    except:
        sends.close()

    # Wait for the last ACK from server.
    while True:
        # Set a 3-minute timeout.
        recvs.settimeout(180)
        try:
            packet, _ = recvs.recvfrom(_BUFFER_SIZE)
            (_, tcp_receiver_seq, tcp_sender_seq,
            fin, syn, rst, psh, ack, urg, adv_window) = unpack_raw_http(packet, 
            parsed_url.hostname, s_addr, s_port)

            if ack == True and fin == syn == rst == psh == urg == False:
                pass
            else:
                raise ValueError("Invalid ACK response!")
            break
        except TimeoutError:
            exit(1)
        # Check if the packet is intended for other processes.
        except FilterRejectException:
            pass
        # Check if a packet intended for our app is illegal.
        except Exception as e:
            pass
    return


def set_up_tcp(sends, recvs, s_addr, remote_hostname,
ip_id, tcp_sender_seq, tcp_receiver_seq):
    """
    Set up connection with the server.
    This function should be called to finish the 3-way handshake with the server when initiating the connection.

    Args:
        sends: A socket instance used to send data to the server.
        recvs: A socket instance used to receive data from the server.
        s_addr: A string representing the IP address of the client in dotted quad-string format.
        remote_hostname: A string representing the remote server. e.g. david.choffnes.com
        ip_id: An int representing the IP identifier.
        tcp_sender_seq: An int representing the TCP sequence initiated by the client.
        tcp_receiver_seq: An int representing the TCP sequence obtained from the server.
    Returns:
        A tuple that contains TCP sender sequence, TCP receiver sequence, IP identifier, and advertised window size.
    """
    d_addr = socket.gethostbyname(remote_hostname)
    s_port = sends.getsockname()[1]

    # Send the 1st SYN packet.
    data = ""
    fin = rst = psh = ack = urg = 0
    syn = 1
    (packet, ip_id) = pack_raw_http(s_addr, d_addr, s_port, ip_id,
    tcp_sender_seq, tcp_receiver_seq, fin, syn, rst, psh, ack, urg, 
    _DEFAULT_ADV_WINDOW, data)
    try:
        n = sends.sendto(packet, (d_addr, 0))
    except:
        sends.close()

    # Wait for SYN/ACK from server.
    while True:
        recvs.settimeout(180)
        try:
            packet, _ = recvs.recvfrom(_BUFFER_SIZE)
            (_, tcp_receiver_seq, tcp_sender_seq,
            fin, syn, rst, psh, ack, urg, adv_window) = unpack_raw_http(packet, 
            remote_hostname, s_addr, s_port)

            if syn == ack == True and fin == rst == psh == urg == False:
                pass
            else:
                raise ValueError("Invalid SYN/ACK response!")
            break
        # Check if the packet is intended for other processes.
        except FilterRejectException:
            pass
        except TimeoutError:
            exit(1)
        # Check if a packet intended for our app is illegal.
        except Exception as e:
            pass
    
    # Send the last ACK to complete three-way handshake.
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
    except:
        sends.close()

    return (tcp_sender_seq, tcp_receiver_seq, ip_id, adv_window)


def raw_http_get(sends, recvs, parsed_url, s_addr,
tcp_sender_seq, tcp_receiver_seq, ip_id, adv_window):
    """
    Get HTML data body from HTTP packets.

    Args:
        sends: A socket instance used to send data to the server.
        recvs: A socket instance used to receive data from the server.
        parsed_url:
        s_addr: A string representing the IP address of the client in dotted quad-string format.
        tcp_sender_seq: An int representing the TCP sequence initiated by the client.
        tcp_receiver_seq: An int representing the TCP sequence obtained from the server.
        ip_id: An int representing the IP identifier.
        adv_window: An int representing the advertised window size.
    Returns:
        A tuple that contains the HTML data body, TCP sender sequence, TCP receiver sequence, and IP identifier.
    """
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
    except Exception as e:
        sends.close()

    # Use TCP connection to receive the HTML file, until FIN response.
    html_doc = b""
    # Set a 3-minute timeout.
    recvs.settimeout(180)
    while True:
        try:
            packet, _ = recvs.recvfrom(_BUFFER_SIZE)
            # Receive a HTTP GET response packet.
            (res, seq_num, tcp_sender_seq,
            fin, syn, rst, psh, ack, urg, adv_window) = unpack_raw_http(packet, 
            parsed_url.hostname, s_addr, sends.getsockname()[1])

            if fin == ack == 1 and syn == rst == urg == psh == 0:
                break
            # Handle FIN/ACK/PSH situation
            elif fin == ack == psh == 1 and syn == rst == urg == 0:
                # Check for out-of-order or duplicate packets.
                if tcp_receiver_seq != seq_num and tcp_receiver_seq != seq_num + 1:
                    raise ValueError("Out of order! Packet discarded.")
                else:
                    tcp_receiver_seq = seq_num

                html_doc += res
                break

            # Check for out-of-order or duplicate packets.
            if tcp_receiver_seq != seq_num and tcp_receiver_seq != seq_num + 1:
                raise ValueError("Out of order! Packet discarded.")
            else:
                tcp_receiver_seq = seq_num

            html_doc += res

            # Acknowledge a received packet.
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
            except Exception as e:
                sends.close()

        except TimeoutError:
            exit(1)
        # Check if the packet is intended for other processes.
        except FilterRejectException:
            pass
        # Check if a packet intended for the client is illegal.
        except Exception as e:
            pass

    head_content_split = html_doc.split(b"\r\n\r\n", 1)

    if head_content_split[0].split(b" ")[1] != b"200":
        exit(1)
    
    return (head_content_split[1], tcp_sender_seq, tcp_receiver_seq, ip_id)


def main():
    """
    Handle the whole connection flow during the connection at a high-level.
    """
    # Set up a commandline interfase.
    args = sys.argv[1:]
    url = args[0] if args else _TEST_URL  # Expect no or exactly one arg.
    parsed_url = urlparse(url)
    url_hostname = parsed_url.hostname

    # Create a raw socket for sending packets.
    with socket.socket(
        socket.AF_INET,
        socket.SOCK_RAW,
        socket.IPPROTO_RAW
        ) as send_s:
        if (send_s == -1):
            exit(1)

        # Creates a raw socket for receiving packets.
        with socket.socket(
            socket.AF_INET,
            socket.SOCK_RAW,
            socket.IPPROTO_TCP
            ) as recv_s:
            if (recv_s == -1):
                exit(1)

            # Get the local IP address.
            try:
                send_s.connect((socket.gethostbyname(url_hostname), 0))
            except Exception as e:
                pass
            s_addr = send_s.getsockname()[0]

            # Pick the first sequence number randomly.
            tcp_sender_seq = random.randint(0, 2**31)
            # SYN packet is the first packet in this connection.
            tcp_receiver_seq = 0

            # Set up the connection using a handshake.
            (tcp_sender_seq, tcp_receiver_seq,
            ip_id, adv_window) = set_up_tcp(send_s, recv_s, s_addr, 
            url_hostname, _INIT_IP_ID, tcp_sender_seq, tcp_receiver_seq)

            # Get HTML data body during the connection.
            (raw_http_get_res, tcp_sender_seq, tcp_receiver_seq,
            ip_id) = raw_http_get(send_s, recv_s, parsed_url, s_addr,
            tcp_sender_seq, tcp_receiver_seq, ip_id, adv_window)

            # Send the last packet and shut down the connection.
            tear_down_tcp(send_s, recv_s, parsed_url, s_addr,
            tcp_sender_seq, tcp_receiver_seq, ip_id, adv_window)

            # Save the HTML data body to the local directory.
            file_name = parsed_url.path.split("/")[-1]
            file_name = file_name if file_name else "index.html"
            with open(file_name, "wb") as file:
                file.write(raw_http_get_res)

    return


if __name__ == "__main__":
    main()