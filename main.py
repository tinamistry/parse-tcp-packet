import dpkt
from dpkt.tcp import TH_FIN
from dpkt.utils import inet_to_str


def analysis_pcap_tcp(fileName):
    sender = '130.245.145.12'
    receiver = ' 128.208.2.198'
    f = open('assignment2.pcap', 'rb')
    pcap = dpkt.pcap.Reader(f)
    flow_counter = 0
    setup = 0
    for ts, buffer in pcap:
        eth = dpkt.ethernet.Ethernet(buffer)
        ip = eth.data
        tcp = ip.data

        source_port = tcp.sport  # source port
        dest_port = tcp.dport  # destination port
        source_ip = inet_to_str(ip.src)
        dest_ip = inet_to_str(ip.dst)

        if source_ip == sender:
            if tcp.flags & dpkt.tcp.TH_SYN:  # if the source is the sender its the beginning
                flow_counter += 1
                print('Flow #' + str(flow_counter))
                print('Source IP: ' + str(source_ip) + " Source Port: " + str(source_port))
                print('Destination IP: ' + str(dest_ip) + " Destination Port: " + str(dest_port))
                first_two_transaction(source_ip, source_port, dest_port, dest_ip)

        if dest_ip == sender:
            if tcp.flags & dpkt.tcp.TH_FIN:
                print(flow_counter)


def first_two_transaction(source_ip, source_port, dest_port, dest_ip):
    string = " "
    sender = '130.245.145.12'
    receiver = ' 128.208.2.198'
    f = open('assignment2.pcap', 'rb')
    pcap = dpkt.pcap.Reader(f)
    transaction = 0
    for ts, buffer in pcap:
        eth = dpkt.ethernet.Ethernet(buffer)
        ip = eth.data
        tcp = ip.data
        sp = tcp.sport  # source port
        dp = tcp.dport  # destination port
        sip = inet_to_str(ip.src)
        dip = inet_to_str(ip.dst)
        if transaction == 1 and source_ip == sender:
            print("Sequence #: " )

            transaction = 2
        if transaction == 2 and source_ip == sender:
            return
        if source_ip == sip and source_port == sp and dest_port == dp and dest_ip == dip:
            transaction = 1



analysis_pcap_tcp('assignment2.pcap')
