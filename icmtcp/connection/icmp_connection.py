from icmtcp.connection.ip_connection import IPConnection
from icmtcp.packet.icmp_packet import ICMPPacket

class ICMPConnection(IPConnection):
    def __init__(self):
        super().__init__()

    def recieve(self) -> ICMPPacket:
        recieved = super()._recieve_packet_raw()
        if recieved == None:
            print("None recieved")
            return

        packet = ICMPPacket()
        packet.decompile(recieved)
        return packet
    
    def _is_valid_packet(self, raw_data: bytes) -> bool:
        try:
            ICMPPacket().decompile(raw_data)
            return True
        except Exception as e:
            return False
        