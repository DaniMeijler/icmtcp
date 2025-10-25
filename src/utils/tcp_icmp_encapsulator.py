
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
