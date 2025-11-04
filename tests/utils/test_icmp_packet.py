import struct
import pytest
from src.utils.icmp_packet import ICMPPacket, ICMP_ECHO_REQUEST_TYPE, ICMP_ECHO_REQUEST_CODE


def test_init_default_values():
    pkt = ICMPPacket()
    assert pkt.type == 0
    assert pkt.code == 0
    assert pkt.id == 0
    assert pkt.seq_num == 0
    assert pkt.payload == b''


def test_init_custom_values():
    pkt = ICMPPacket(type=ICMP_ECHO_REQUEST_TYPE, code=ICMP_ECHO_REQUEST_CODE, id=1234, seq_num=5, payload=b'test')
    assert pkt.type == ICMP_ECHO_REQUEST_TYPE
    assert pkt.code == ICMP_ECHO_REQUEST_CODE
    assert pkt.id == 1234
    assert pkt.seq_num == 5
    assert pkt.payload == b'test'


def test_raw_packet_structure():
    pkt = ICMPPacket(type=ICMP_ECHO_REQUEST_TYPE, code=ICMP_ECHO_REQUEST_CODE, id=1234, seq_num=1, payload=b'test payload')
    raw = pkt.raw_packet()
    t, c, checksum, pid, seq = struct.unpack('!BBHHH', raw[:8])
    assert t == ICMP_ECHO_REQUEST_TYPE
    assert c == ICMP_ECHO_REQUEST_CODE
    assert pid == 1234
    assert seq == 1
    assert raw[8:] == b'test payload'


def test_checksum_calculation():
    pkt = ICMPPacket(type=8, code=0, id=1, seq_num=1, payload=b'AAAA')
    c = pkt.calculate_checksum()
    assert isinstance(c, int)
    assert 0 <= c <= 0xFFFF


def test_from_bytes_valid_packet():
    header = struct.pack('!BBHHH', ICMP_ECHO_REQUEST_TYPE, ICMP_ECHO_REQUEST_CODE, 0, 42, 7)
    raw = header + b'hello'
    pkt = ICMPPacket()
    pkt.from_bytes(raw)
    assert pkt.type == ICMP_ECHO_REQUEST_TYPE
    assert pkt.code == ICMP_ECHO_REQUEST_CODE
    assert pkt.id == 42
    assert pkt.seq_num == 7
    assert pkt.payload == b'hello'


def test_from_bytes_invalid_input():
    pkt = ICMPPacket()
    with pytest.raises(TypeError):
        pkt.from_bytes('not-bytes')
    with pytest.raises(ValueError):
        pkt.from_bytes(b'123')
