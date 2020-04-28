import dpkt
import sys


# main method
def main():
    file_name = "assignment3_my_arp.pcap"
    f = open(file_name, 'rb')
    pcap = dpkt.pcap.Reader(f)
    read_pcap_arp(pcap)
    sort_arp()
    print(len(arp_packets))

    print_arp_request()
    print_arp_response()


# prints out the first ARP request packet
def print_arp_request():
    print("-------------------------------------------ARP Request-------------------------------------------")
    print("Hardware Type: " + str(int.from_bytes(arp_requests[0][14:16], "big")))
    print("Protocol Type: 0x" + str(arp_requests[0][16:18].hex()))
    print("Hardware Size: " + str(arp_requests[0][18]))
    print("Protocol Size: " + str(arp_requests[0][19]))
    print("Opcode: request (" + str(int.from_bytes(arp_requests[0][20:22], "big")) + ")")
    print("Sender MAC Address: " + get_mac_addr(arp_requests[0][22:28].hex()))
    print("Sender IP Address: " + get_ip(arp_requests[0][28:32]))
    print("Target MAC Address: " + get_mac_addr(arp_requests[0][32:38].hex()))
    print("Target IP Address: " + get_ip(arp_requests[0][38:42]))


# prints out the first ARP response packet
def print_arp_response():
    print("-------------------------------------------ARP Response-------------------------------------------")
    print("Hardware Type: " + str(int.from_bytes(arp_responses[0][14:16], "big")))
    print("Protocol Type: 0x" + str(arp_responses[0][16:18].hex()))
    print("Hardware Size: " + str(arp_responses[0][18]))
    print("Protocol Size: " + str(arp_responses[0][19]))
    print("Opcode: response (" + str(int.from_bytes(arp_responses[0][20:22], "big")) + ")")
    print("Sender MAC Address: " + get_mac_addr(arp_responses[0][22:28].hex()))
    print("Sender IP Address: " + get_ip(arp_responses[0][28:32]))
    print("Target MAC Address: " + get_mac_addr(arp_responses[0][32:38].hex()))
    print("Target IP Address: " + get_ip(arp_responses[0][38:42]))


# sorts the ARP packets into request and response packets
def sort_arp():
    for arp in arp_packets:
        if arp[20:22] == b'\x00\x01':
            arp_requests.append(arp)
        else:
            arp_responses.append(arp)


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
arp_requests = []
arp_responses = []

if __name__ == '__main__':
    main()
