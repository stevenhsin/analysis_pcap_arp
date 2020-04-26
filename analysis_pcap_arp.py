import dpkt
import sys


# main method
def main():
    file_name = "assignment3_my_arp.pcap"
    f = open(file_name, 'rb')
    pcap = dpkt.pcap.Reader(f)
    read_pcap_arp(pcap)
    print(all_packets[0])
    print(all_packets[0][13])
    print(len(arp_packets))


# reads the packets listed in pcap file
def read_pcap_arp(pcap):
    for ts, buf in pcap:
        all_packets.append(buf)
        # ARP (0x0806)
        if buf[13] == 6:
            arp_packets.append(buf)


all_packets = []
arp_packets = []

if __name__ == '__main__':
    main()
