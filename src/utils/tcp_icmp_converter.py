
from .icmp_packet import ICMPPacket, ICMP_ECHO_REQUEST_TYPE, ICMP_ECHO_REQUEST_CODE, ICMP_PAYLOAD_MAX_SIZE
from .logger import Logger
import pickle

@staticmethod
def encapsule_tcp_data(tcp_data, id, dest_host, dest_port):
    """
    @brief: Encapsulate TCP data into ICMP packets
    @param tcp_data: raw TCP data to be encapsulated
    @returns: list of ICMP packets
    """
    packet_length = len(tcp_data)
    i = 1
    fragments = []
    fragments.append(create_header_fragment(tcp_data, dest_host, dest_port, id))

    while tcp_data != b"":
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

@staticmethod
def decapsule_icmp_packet(icmp_tcp_fragments):
    """
    @brief: Decapsulate ICMP packets to retrieve TCP data
    @param icmp_tcp_fragments: list of ICMP packets containing TCP data
    @returns: raw TCP data, dest_host, dest_port
    """
    # Sort fragments based on sequence number
    icmp_tcp_fragments.sort(key=lambda pkt: pkt.seq_num)

    header_fragment = icmp_tcp_fragments.pop(0)
    header_info = pickle.loads(header_fragment.payload)
    dest_host = header_info["dest_host"]
    dest_port = header_info["dest_port"]
    packet_length = header_info["tcp_packet_length"]

    tcp_data = b""
    for fragment in icmp_tcp_fragments:
        tcp_data += fragment.payload
    
    if len(tcp_data) != packet_length:
        raise Exception("Missing data: reconstructed TCP data length does not match header info")
    
    return tcp_data, dest_host, dest_port

