import socket
import pcapy
import datetime
from struct import *

myIP = '192.168.153.131'

def main():
    dev = pcapy.findalldevs()[0]

    cap = pcapy.open_live(dev, 65536, 1, 0) #dev, snaplen, promiscious mode, timeout

    while(1):
        (header, packet) = cap.next()
        #print ('%s: captured %d bytes, truncated to %d bytes' %(datetime.datetime.now(),header.getlen(), header.getcaplen()))
        parse_packet(packet)

def isHttpRequest(data):
    method = ['GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'OPTIONS']
    for name in method:
        if(data[0:len(name)] == name):
            return 1
        return 0


def parse_packet(packet):
    eth_length = 14
    eth_header = packet[:eth_length]
    eth = unpack('!6s6sH', eth_header) #6char + 6char + 2int = 8 / This format string will take out required fields of header packet
    eth_protocol = socket.ntohs(eth[2])
    
    if eth_protocol == 8: #if ip
        ip_header = packet[eth_length:eth_length+20]
        iph = unpack('!BBHHHBBH4s4s', ip_header)
        
        iph_length = (iph[0] & 0xF) * 4
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9]);
        
        
        if protocol == 6:    #if tcp and outbound
            tcp_header = packet[iph_length+eth_length:iph_length+eth_length+20]
            tcph = unpack('!HHLLBBHHH', tcp_header)

            s_port = tcph[0]
            d_port = tcph[1]
            sequence = tcph[2]
            tcph_length = tcph[4] >> 4
            h_size = eth_length + iph_length + tcph_length * 4
            data_size = len(packet) - h_size
            data = packet[h_size:]
            
            if isHttpRequest(data): # if http reqeust
                print 'HTTP========================================================'

                sock_for = socket(AF_INET, SOCK_STREM)
                sock_for.connect((d_addr, 80))
                sock_back.socket(AF_INET, SOCK_STREAM)
                sock_back.connect((s_addr, 80))

            else:
                sock_for = socket(AF_INET, SOCK_STREAM)
                sock_for.connect((d_addr, d_port))

                sock_back = socket(AF_INET, SOCK_STREAM)
                sock_back.connect((s_addr, s_port))
                


                #make fake packet

                sock_for.close()
                sock_back.close()


if __name__ == '__main__':
    main()
