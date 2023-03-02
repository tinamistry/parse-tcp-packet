import dpkt
from dpkt.tcp import TH_FIN
from dpkt.utils import inet_to_str


def analysis_pcap_tcp(fileName):
    sender = '130.245.145.12'
    receiver = ' 128.208.2.198'
    f = open('assignment2.pcap', 'rb')
    pcap = dpkt.pcap.Reader(f)
    flow_counter = 0
    transaction_counter = 0
    for ts, buffer in pcap:
        eth = dpkt.ethernet.Ethernet(buffer)
        ip = eth.data
        tcp = ip.data

        source_port = tcp.sport  # source port
        dest_port = tcp.dport  # destination port
        source_ip = inet_to_str(ip.src)
        dest_ip = inet_to_str(ip.dst)

        source_string = 'The Source port :'
        print(source_string)
        print(source_port)
        print('The destination port is: ')
        print(dest_port)
        print('The source ip is: ')
        print(source_ip)
        print('The destination ip address is: ')
        print(dest_ip)

        # if tcp.flags & dpkt.tcp.TH_SYN:
        # print(bool(tcp.flags & dpkt.tcp.TH_SYN))
        # if tcp.flags & dpkt.tcp.TH_FIN:
        # print(bool(tcp.flags & dpkt.tcp.TH_FIN))

        # parse from tcp until fin -> 1 flow


analysis_pcap_tcp('assignment2.pcap')
