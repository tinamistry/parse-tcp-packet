import dpkt
from dpkt.tcp import TH_FIN
from dpkt.utils import inet_to_str


def analysis_pcap_tcp(fileName):
    sender = '130.245.145.12'
    receiver = '128.208.2.198'
    f = open('assignment2.pcap', 'rb')
    pcap = dpkt.pcap.Reader(f)
    flow_counter = 0
    setup = 0
    count = 0
    for ts, buffer in pcap:
        eth = dpkt.ethernet.Ethernet(buffer)
        ip = eth.data
        tcp = ip.data

        source_port = tcp.sport  # source port
        dest_port = tcp.dport  # destination port
        source_ip = inet_to_str(ip.src)
        dest_ip = inet_to_str(ip.dst)

        if source_ip == sender and tcp.flags & dpkt.tcp.TH_SYN:  # if the source is the sender its the beginning
            count += 1
            flow_counter += 1
            print('Flow #' + str(flow_counter))
            print('Source IP: ' + str(source_ip) + " Source Port: " + str(source_port)
                  + ' Destination IP: ' + str(dest_ip) + " Destination Port: " + str(dest_port))
            t(source_ip, dest_ip, source_port, dest_port)


def t(sip, dip, sp, dp):
    sender = '130.245.145.12'
    receiver = '128.208.2.198'
    f = open('assignment2.pcap', 'rb')
    pcap = dpkt.pcap.Reader(f)
    i = 0
    j = 0
    for ts, buffer in pcap:
        eth = dpkt.ethernet.Ethernet(buffer)
        ip = eth.data
        tcp = ip.data
        source_port = tcp.sport  # source port
        dest_port = tcp.dport  # destination port
        source_ip = inet_to_str(ip.src)
        dest_ip = inet_to_str(ip.dst)

        if source_ip == sip and dest_ip == dip and dest_port == dp and source_port == sp:
            i += 1
            if i > 2:
                j += 1
                if j > 2:
                    break
                print("Transaction #" + str(j) + " Sequence #: " + str(tcp.seq) + " Ack #: " + str(
                    tcp.ack) + " Receive Window Size: " + str(tcp.win))


def get_window_size(sport):
    sender = '130.245.145.12'
    receiver = '128.208.2.198'
    f = open('assignment2.pcap', 'rb')
    pcap = dpkt.pcap.Reader(f)
    for ts, buffer in pcap:
        eth = dpkt.ethernet.Ethernet(buffer)
        ip = eth.data
        tcp = ip.data

        source_port = tcp.sport  # source port
        dest_port = tcp.dport  # destination port
        source_ip = inet_to_str(ip.src)
        dest_ip = inet_to_str(ip.dst)

        if source_ip == receiver and tcp.flags & dpkt.tcp.TH_FIN and sport == dest_port:
            return tcp.win


analysis_pcap_tcp('assignment2.pcap')
