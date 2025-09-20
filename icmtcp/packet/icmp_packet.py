from scapy.all import ICMP, Raw, Packet
from icmtcp.packet.ip_packet import IPPacket

class ICMPPacket(IPPacket):
    def __init__(self):
        self.code = 0
        self.type = 0
        self.seq = 0
        self.id = 0

    def get_icmp_layer(self) -> ICMP:
        return ICMP(type=self.type, code=self.code, seq=self.seq, id=self.id)
    
    def get_packet(self) -> Packet:
        return self.get_ip_layer() / self.get_icmp_layer() / Raw(load=self.payload)

    def compile(self) -> bytes:
        icmp_layer = self.get_icmp_layer()
        data = Raw(load=self.payload)
        return bytes(icmp_layer / data)
    
    def decompile(self, raw_bytes: bytes) -> None:
        super().decompile(raw_bytes)
        icmp = ICMP(self.payload)
        self.code = icmp.code
        self.type = icmp.type
        self.id = icmp.id
        self.seq = icmp.seq
        self.payload = icmp.payload.load
        