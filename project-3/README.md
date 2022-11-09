## Group Information

Name: , NUID:  
Name: Jiazhe Chen, NUID: 002162461  

## High Level Approach

## Detailed Description

## Challenges Faced

## Tips from TA

1. build raw socket connection for some url to get file in packets  
2. send first SYN (flags in tcp header) packet (can use random number as the sequence number, will start from that number when receiving) ,advertised windows size 5840, pack ip header, tcp header & data (empty in the first packet)  
3. get SYN/ACK from server, unpack ip header, tcp header & data  
4. send ACK back server (pack everything) - complete the 3-way handshake  
5. get packets from the server (unpack everything) - need to ACK them everytime  
6. increase the window size by 1 every successful ACK, timeout 3 seconds (or try it on your own) and reset it to 1  
7. rearrange packets using sequence number to form the whole file  
8. FIN flag to close, socket.close()  
9. use wireshark to detect errors. if tcp header or ip header is not correct, will get error in wireshark. if install in the local machine, need to configure the host name of the virtual machine. otherwise use the hostname of the virtual machine.  

misc1:  
verification on IP header  
version  
header length  
protocol number  
source address  
destination address  
checksum  
misc2:  
verification on TCP header  
sequence number source port and dest port  
misc3:  
allow fragments in ip header  
should try start to make packets first  

1 send http request first SYN packet a random sequence number then keep tracking that, will be that number plus  
2 get SYC back ACK number 0 to some random number (say 8000 or 9000)  
3 flags in the tcp header  
4 complete the tcp header  


Questions for TA:
1. Can we assume IPv4 and no IPv6 packets? Assumptions made at:
    inet_ntoa()
    gethostbyname()