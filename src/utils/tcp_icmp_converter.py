
from .icmp_packet import ICMPPacket
from .logger import Logger

ICMP_PAYLOAD_MAX_SIZE = 1472
ICMP_ECHO_REQUEST_TYPE = 8
ICMP_ECHO_REPLY_TYPE = 0
ICMP_ECHO_REQUEST_CODE = 0
ICMP_ECHO_REPLY_CODE = 0

@staticmethod
def encapsule_tcp_data(tcp_data, id):
    """
    @brief: Encapsulate TCP data into ICMP packets
    @param tcp_data: raw TCP data to be encapsulated
    @returns: list of ICMP packets
    """
    packet_length = len(tcp_data)
    i = 0
    fragments = []

    while tcp_data != b"":
        fragment_payload = tcp_data[:ICMP_PAYLOAD_MAX_SIZE]
        tcp_data = tcp_data[ICMP_PAYLOAD_MAX_SIZE:]

        icmp_packet = ICMPPacket(
            type=ICMP_ECHO_REQUEST_TYPE,
            code=ICMP_ECHO_REQUEST_CODE,
            id=id, 
            seq_num=i,
            payload=fragment_payload,
        )
        fragments.append(icmp_packet)
        i += 1
    
    return fragments

def decapsule_icmp_packet(icmp_tcp_fragments):
    """
    @brief: Decapsulate ICMP packets to retrieve TCP data
    @param icmp_tcp_fragments: list of ICMP packets containing TCP data
    @returns: raw TCP data
    """
    # Sort fragments based on sequence number
    icmp_tcp_fragments.sort(key=lambda pkt: pkt.seq_num)

    tcp_data = b""
    for fragment in icmp_tcp_fragments:
        tcp_data += fragment.payload
    
    return tcp_data

