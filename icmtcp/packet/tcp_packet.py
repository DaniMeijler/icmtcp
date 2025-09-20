from scapy.all import TCP, Raw, Packet
from icmtcp.packet.ip_packet import IPPacket

class TCPPacket(IPPacket):
    def __init__(self):
        self.src_port = 0
        self.dst_port = 0
        self.seq = 0
        self.ack = 0
        self.flags = ""

    def get_tcp_layer(self) -> TCP:
        return TCP(sport=self.src_port, dport=self.dst_port, seq=self.seq, ack=self.ack,
                   flags=self.flags)
    
    def get_packet(self) -> Packet:
        return self.get_ip_layer() / self.get_tcp_layer() / Raw(load=self.payload)

    def compile(self) -> bytes:
        tcp_layer = self.get_tcp_layer()
        data = Raw(load=self.payload)
        return bytes(tcp_layer / data)
    
    def decompile(self, raw_bytes: bytes) -> None:
        super().decompile(raw_bytes)   
        try:
            tcp= TCP(self.payload)
        except Exception as e:
            raise Exception("can't compile non tcp packet")
        
        self.src_port = tcp.sport
        self.dst_port = tcp.dport
        self.ack = tcp.ack
        self.seq = tcp.seq
        self.flags = tcp.flags
        self.payload = tcp.payload.load
        