import dpkt
import sys


# main method
def main():
    file_name = "assignment3_my_arp.pcap"
    f = open(file_name, 'rb')
    pcap = dpkt.pcap.Reader(f)
    read_pcap_arp(pcap)
    print(arp_packets[0][12:14])  # ARP
    print(arp_packets[0][16:18])  # IP Protocol
    print(arp_packets[0][20:22])  # Opcode
    print(arp_packets[1][20:22])

    print(arp_packets[0][22:28])  # Sender Mac Address
    print(arp_packets[0][32:38])  # Target Mac Address
    print(arp_packets[1][22:28].hex())  # Sender Mac Address

    print("Sender MAC Address: " + get_mac_addr(arp_packets[1][22:28].hex()))  # works in returning MAC Address with proper formatting

    print(arp_packets[1][32:38].hex())  # Target Mac Address

    print("Hardware Size: " + str(arp_packets[0][18]))
    print(get_ip(arp_packets[0][28:32]))  # Sender IP Address
    print(get_ip(arp_packets[0][38:42]))  # Target IP Address
    print(len(arp_packets))


# returns the source/destination IP address
def get_ip(ip_in_hex):
    new_ip = ''
    for num in ip_in_hex:
        new_ip = new_ip + str(num) + "."

    new_ip = new_ip[0:new_ip.__len__() - 1]
    return new_ip


# returns the MAC addresses as a string
def get_mac_addr(addr_in_hex):  # addr_in_hex should look something like arp_packets[1][22:28].hex()
    mac_addr = ""
    count = 0
    for num in addr_in_hex:
        mac_addr = mac_addr + str(num)
        count += 1
        if count == 2:
            mac_addr = mac_addr + ":"
            count = 0
    return mac_addr[:-1]


# reads the packets listed in pcap file
def read_pcap_arp(pcap):
    for ts, buf in pcap:
        all_packets.append(buf)
        # ARP (0x0806)
        if buf[12:14] == b'\x08\x06':
            arp_packets.append(buf)


all_packets = []
arp_packets = []

if __name__ == '__main__':
    main()
