from scapy.all import IP, Raw

class IPPacket(object):
    def __init__(self, src_ip: str, dst_ip: str, payload: str):
        self._src_ip = src_ip
        self._dst_ip = dst_ip
        self._payload = payload

    def compile(self) -> bytes:
        packet = IP(src=self._src_ip,
                    dst=self._dst_ip) / Raw(load=self._payload)
        return bytes(packet)
    
    def decompile(self, raw_bytes: bytes) -> None:
        packet = IP(raw_bytes)
        print(packet.show())