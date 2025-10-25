import pickle
from .icmp_packet import ICMPPacket, ICMP_ECHO_REQUEST_TYPE, ICMP_ECHO_REQUEST_CODE, ICMP_PAYLOAD_MAX_SIZE
from .logger import Logger
from .tcp_icmp_converter import decapsule_icmp_packet

logger = Logger(__name__)

class ICMTCPFragmentReciever:
    def __init__(self, id):
        self.recieved_fragments = []
        self.id = id
        self.total_tcp_bytes = None
        self.recieved_bytes = 0
        self.dest_host = None
        self.dest_port = None

    def recieve_fragment(self, icmp_packet):
        """Handle a received ICMP fragment"""
        if icmp_packet.id != self.id:
            logger.error(f"Received fragment with unexpected ID {icmp_packet.id}, expected {self.id}")
            raise ValueError("Unexpected fragment ID")
        
        if icmp_packet.seq_num == 0:
            # This is the header fragment
            header_info = pickle.loads(icmp_packet.payload)
            self.total_tcp_bytes = header_info["tcp_packet_length"]
            self.dest_host = header_info["dest_host"]
            self.dest_port = header_info["dest_port"]
            logger.debug(f"Received header fragment: total_tcp_bytes={self.total_tcp_bytes}, dest_host={self.dest_host}, dest_port={self.dest_port}")
            return
        
        if icmp_packet not in self.recieved_fragments:
            self.recieved_fragments.append(icmp_packet)
            self.recieved_bytes += len(icmp_packet.payload)

    def is_complete(self):
        """Check if all fragments have been received"""
        if self.total_tcp_bytes is None:
            return False
        
        return self.recieved_bytes >= self.total_tcp_bytes
    
    def reconstruct_tcp_data(self):
        if not self.is_complete():
            logger.error("Cannot reconstruct TCP data: fragments are incomplete")
            raise ValueError("Fragments are incomplete")
        
        self.recieved_fragments.sort(key=lambda pkt: pkt.seq_num)
        tcp_data = b""
        for fragment in self.recieved_fragments:
            tcp_data += fragment.payload
        
        return tcp_data, self.dest_host, self.dest_port
