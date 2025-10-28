
from .icmp_packet import ICMPPacket, ICMP_ECHO_REQUEST_TYPE, ICMP_ECHO_REQUEST_CODE, ICMP_PAYLOAD_MAX_SIZE
from .logger import Logger
import pickle

logger = Logger(__name__)

@staticmethod
def fragment(tcp_data, id, dest_host, dest_port):
    """
    @brief: Fragment TCP data into ICMP packets
    @param tcp_data: raw TCP data to be fragmented
    @returns: list of ICMP packets
    """
    packet_length = len(tcp_data)
    logger.debug(f"Fragmenting TCP data of length {packet_length} with ID {id}")
    i = 1
    fragments = []
    fragments.append(create_header_fragment(tcp_data, dest_host, dest_port, id))

    while tcp_data != b"":
        if packet_length < ICMP_PAYLOAD_MAX_SIZE:
            fragment_payload = tcp_data
            tcp_data = b""
        
        else:
            fragment_payload = tcp_data[:ICMP_PAYLOAD_MAX_SIZE]
            tcp_data = tcp_data[ICMP_PAYLOAD_MAX_SIZE:]

        packet = ICMPPacket(
            type=ICMP_ECHO_REQUEST_TYPE,
            code=ICMP_ECHO_REQUEST_CODE,
            id=id, 
            seq_num=i,
            payload=fragment_payload,
        )
        fragments.append(packet)
        i += 1
    
    return fragments

@staticmethod
def create_header_fragment(tcp_data, dest_host, dest_port, id):
    """
    @brief: Create the header fragment containing metadata about the TCP data
    @param tcp_data: raw TCP data
    @returns: ICMP packet representing the header fragment
    """
    packet_payload = {
        "tcp_packet_length": len(tcp_data),
        "dest_host": dest_host,
        "dest_port": dest_port
    }
    header_payload = pickle.dumps(packet_payload)

    header_fragment = ICMPPacket(
        type=ICMP_ECHO_REQUEST_TYPE,
        code=ICMP_ECHO_REQUEST_CODE,
        id=id,  
        seq_num=0, # header fragment seq num
        payload=header_payload
    )

    return header_fragment