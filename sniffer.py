import socket
import struct
import textwrap


TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '


def main():
    # try:
    #     s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    # except socket.error, msg:
    #     print ('Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
    #     sys.exit()

    # socket.ntohs(3) tells capture everything including ethernet frames.
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, add = conn.recvfrom(65535)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame')
        print(TAB_1 + 'Destination : {}, Source : {}, Protocal : {}'.format(
            dest_mac, src_mac, eth_proto))

        # 8 for ipv4
        if eth_proto == 8:
            (version, header_length, ttl, proto,
             src, target, data) = ipv4_packet(data)
            print(TAB_1 + 'IPv4 Packet:')
            print(
                TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
            print(
                TAB_2 + 'Protocal: {}, Source: {}, Target: {}'.format(proto, src, target))

            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print(TAB_1 + 'ICMP Packet:')
                print(
                    TAB_2 + 'Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
               # bytes.fromhex(str(data)).decode('utf-8')

                print(TAB_2 + 'Data: {}'.format(data))
                # print(format_multi_line(DATA_TAB_3, data))

            elif proto == 6:
                src_port, dest_port, sequence, acknowlegement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin = tcp_packet(
                    data)
                print(TAB_1 + 'TCP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(
                    src_port, dest_port))
                print(
                    TAB_2 + 'Sequence: {}, Acknowledgement: {}'.format(sequence, acknowlegement))
                print(TAB_2 + 'Flags: {}')
                print(TAB_3 + 'URG: {},ACK: {},PSH: {},RST: {},SYN: {},FIN: {}'.format(
                    flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                # bytes.fromhex(str(data)).decode('utf-8')
                print(TAB_2 + 'Data: {}'.format(data))
                # print(format_multi_line(DATA_TAB_3, data))

            elif proto == 17:
                src_port, dest_port, size, data = udp_packet(data)
                print(TAB_1 + 'UDP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length/Size: {}'.format(
                    src_port, dest_port, size))
                # bytes.fromhex(str(data)).decode('utf-8')
                # print(TAB_2 + 'Data: {}'.format(data))
                # print(format_multi_line(DATA_TAB_3, data))
            else:
                print(TAB_1 + 'Data: {}'.format(data))
                print(format_multi_line(DATA_TAB_2, data))
        else:
            print(TAB_1 + 'Data: {}'.format(data))

            # print('Data:')
            # bytes.fromhex(str(data)).decode('utf-8')
            # print(format_multi_line(DATA_TAB_1, data))

            # Unpack ethernet frame
            # Ethernet frame
            # SYNC(8byte)-RECEIVER(6byte)-SENDER(6byte)-TYPE(2byte)-PAYLOAD(46-1500byte)-CRC(4byte)
            # Sync isnt in the data**


def ethernet_frame(data):
    # 6s for 6 byte and H for unsigned integer
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    # get_mac_add() coverts mac into readable format for users
    return get_mac_add(dest_mac), get_mac_add(src_mac), socket.htons(proto), data[14:]


# format the mac into standard covention adn returns it
# 00:50:3E:E4:4C:00 (48bit or 6 byte)
def get_mac_add(bytes_add):
    bytes_str = map('{:02x}'.format, bytes_add)
    mac_add = ':'.join(bytes_str).upper()
    return mac_add

# Unpackking the IPv4 packet
# IPv4 header:
# https://foren6.files.wordpress.com/2011/04/ip-header-v41.png


def ipv4_packet(data):
    version_header_length = data[0]
    # The first byte consists of version and header length
    # Right shifting by 4 gives us the version
    version = version_header_length >> 4
    header_length = (version_header_length & 15)*4
    ttl, proto, src, target = struct.unpack('!8x B B 2x 4s 4s', data[:20])
    return (version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:])


# format ip address
def ipv4(add):
    return '.'.join(map(str, add))


# Unpack ICMP packet, Protocal = 1
# https://www.researchgate.net/profile/Md_Nazmul_Islam/publication/316727741/figure/fig5/AS:614213521268736@1523451323001/ICMP-packet-structure.png
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]


# Unpack TCP packet, Protocal = 6
# https://www.computerhope.com/jargon/p/packet.jpg

def tcp_packet(data):
    (src_port, dest_port, sequence, acknowlegement,
     offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = (offset_reserved_flags & 1)

    return src_port, dest_port, sequence, acknowlegement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin


# Unpacks UDP segment, Protocal = 17
# https://lh3.googleusercontent.com/proxy/o5fE5cdzej4ion90IP7TQ-mXZljxjiKO4ft8xcEvpRKvV3a3KSThLNT5ThRwOyoX-DTLqmklmPFKS-2c0oCZie5yoiNH7b-pq5j_mks
def udp_packet(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]


# Formats multi-line data
# Breaks into line by line
def format_multi_line(prefix, string, size=80):
    size = len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


main()
