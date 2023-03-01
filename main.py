import dpkt
def analysis_pcap_tcp(fileName):
    sender = '130.245.145.12'
    receiver = ' 128.208.2.198'
    f = open('assignment2.pcap','rb')
    pcap = dpkt.pcap.Reader(f)
    for ts, buffer in pcap:
       eth = dpkt.ethernet.Ethernet(buffer)
       ip = eth.data
       print(ip)
       print(ip.src)
       print(ip.dst)
       print('\n')






analysis_pcap_tcp('assignment2.pcap')
