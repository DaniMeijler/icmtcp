from .logger import Logger
import struct

ICMP_PACKET_SIZE = 4096
ICMP_PAYLOAD_MAX_SIZE = 1472
ICMP_ECHO_REQUEST_TYPE = 8
ICMP_ECHO_REPLY_TYPE = 0
ICMP_ECHO_REQUEST_CODE = 0
ICMP_ECHO_REPLY_CODE = 0

logger = Logger(__name__)

class ICMPPacket:
    def __init__(self, type=0, code=0, id=0, seq_num=0, payload=b''):
        self.type = type
        self.code = code
        self.id = id
        self.seq_num = seq_num
        self.payload = payload

    def raw_packet(self) -> bytes:
        """
        @brief Construct the raw bytes of the ICMP packet
        @returns: raw bytes of the ICMP packet
        """
        header = struct.pack('!BBHHH', self.type, self.code, self.calculate_checksum(),
                              self.id, self.seq_num)
        return header + self.payload
    
    def calculate_checksum(self) -> int:
        """
        @brief Calculate the checksum for the ICMP packet (RFC 1071)
        @returns: checksum as an integer
        """
        header = struct.pack("!BBHHH", self.type, self.code, 0, self.id, self.seq_num)
        payload = self.payload

        packet = header + payload

        # pad to even length
        if len(packet) % 2 == 1:
            packet += b"\x00"

        total = 0
        for i in range(0, len(packet), 2):
            word = (packet[i] << 8) + packet[i + 1]
            total += word

        while (total >> 16) > 0:
            total = (total & 0xFFFF) + (total >> 16)

        checksum = (~total) & 0xFFFF
        return checksum
    
    def from_bytes(self, raw_data: bytes):
        """
        @brief Parse raw bytes into ICMP packet fields
        @param raw_data: raw bytes of the ICMP packet
        """
        
        if not isinstance(raw_data, (bytes)):
            raise TypeError("raw_data must be bytes")

        if len(raw_data) < 4:
            raise ValueError("Raw data is too short to be a valid ICMP packet.")

        self.type, self.code, self.checksum, self.id, self.seq_num = struct.unpack('!BBHHH', raw_data[:8])
        self.payload = raw_data[8:]