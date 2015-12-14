import socket, sys, re
from struct import *

'python.org/doc/socket'
def get_socket():
    # the public network interface
    HOST = socket.gethostbyname(socket.gethostname())

    # create a raw socket and bind it to the public interface
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

    s.bind((HOST, 0)) 

    # Include IP headers
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # receive all packages
    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON) 

    return s

def to_num(r):
    return map(ord, list(r))

def to_hex(r):
    return map(hex, to_num(r))

def get_proto(ip):
    return ip[9]

def sum_proto(s, n):
    protocols = []
    for i in range(n):
        r = to_num(s.recv(65535))
        protocols.append(get_proto(r))
    return protocols


if __name__ == '__main__':
    #Packet sniffer in python for Linux
    #Sniffs only incoming TCP packet
    'http://www.binarytides.com/python-packet-sniffer-code-linux/'

    #create an INET, STREAMing socket
    try:
        #s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s = get_socket()
    except socket.error , msg:
        print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
        sys.exit()

    # receive a packet
    while True:
        packet = s.recvfrom(65565)
        
        #packet string from tuple
        packet = packet[0]
        
        #take first 20 characters for the ip header
        ip_header = packet[0:20]
        
        #now unpack them :)
        iph = unpack('!BBHHHBBH4s4s' , ip_header)
        
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        
        iph_length = ihl * 4
        
        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8]);
        d_addr = socket.inet_ntoa(iph[9]);
        
        if protocol != 6 or not s_addr.startswith('192.168.1.1'):
            continue

        #print 'Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)


        tcp_header = packet[iph_length:iph_length+20]
        
        #now unpack them :)
        tcph = unpack('!HHLLBBHHH' , tcp_header)
        
        source_port = tcph[0]
        dest_port = tcph[1]
        sequence = tcph[2]
        acknowledgement = tcph[3]
        doff_reserved = tcph[4]
        tcph_length = doff_reserved >> 4
        
        #print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length)

        
        h_size = iph_length + tcph_length * 4
        data_size = len(packet) - h_size
        
        #get data from the packet
        data = packet[h_size:]
        
        if dest_port == 80 and data_size > 0:
            #print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) 
            heads = data.split('\n')
            for head in heads:
                if re.match('Host', head, re.I):
                    print 'Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)
                    print heads[0]
                    print head 
                    print
                    break

