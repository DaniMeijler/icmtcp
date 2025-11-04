import pickle
import pytest
from src.utils.icmtcp_fragment_reciever import ICMTCPFragmentReciever
from src.utils.icmp_packet import ICMPPacket


def test_init():
    r = ICMTCPFragmentReciever(1)
    assert r.id == 1
    assert r.recieved_fragments == []
    assert r.total_tcp_bytes is None


def test_receive_header_fragment():
    r = ICMTCPFragmentReciever(1)
    header = {
        'tcp_packet_length': 11,
        'dest_host': 'example.com',
        'dest_port': 80
    }
    pkt = ICMPPacket(type=8, code=0, id=1, seq_num=0, payload=pickle.dumps(header))
    r.recieve_fragment(pkt)
    assert r.total_tcp_bytes == 11
    assert r.dest_host == 'example.com'


def test_receive_data_fragments_in_order():
    r = ICMTCPFragmentReciever(1)
    header = {'tcp_packet_length': 11, 'dest_host': 'example.com', 'dest_port': 80}
    r.recieve_fragment(ICMPPacket(type=8, code=0, id=1, seq_num=0, payload=pickle.dumps(header)))
    r.recieve_fragment(ICMPPacket(type=8, code=0, id=1, seq_num=1, payload=b'Hello '))
    r.recieve_fragment(ICMPPacket(type=8, code=0, id=1, seq_num=2, payload=b'World'))
    assert len(r.recieved_fragments) == 2
    assert r.recieved_bytes == len(b'Hello World')


def test_receive_data_fragments_out_of_order():
    r = ICMTCPFragmentReciever(1)
    header = {'tcp_packet_length': 11, 'dest_host': 'example.com', 'dest_port': 80}
    r.recieve_fragment(ICMPPacket(type=8, code=0, id=1, seq_num=0, payload=pickle.dumps(header)))
    r.recieve_fragment(ICMPPacket(type=8, code=0, id=1, seq_num=2, payload=b'World'))
    r.recieve_fragment(ICMPPacket(type=8, code=0, id=1, seq_num=1, payload=b'Hello '))
    data, host, port = r.reconstruct_tcp_data()
    assert data == b'Hello World'


def test_receive_duplicate_fragment():
    r = ICMTCPFragmentReciever(1)
    header = {'tcp_packet_length': 5, 'dest_host': 'example.com', 'dest_port': 80}
    r.recieve_fragment(ICMPPacket(type=8, code=0, id=1, seq_num=0, payload=pickle.dumps(header)))
    f = ICMPPacket(type=8, code=0, id=1, seq_num=1, payload=b'Hello')
    r.recieve_fragment(f)
    r.recieve_fragment(f)
    assert len(r.recieved_fragments) == 1


def test_invalid_fragment_id():
    r = ICMTCPFragmentReciever(1)
    with pytest.raises(ValueError):
        r.recieve_fragment(ICMPPacket(type=8, code=0, id=2, seq_num=1, payload=b'bad'))


def test_is_complete_and_reconstruct():
    r = ICMTCPFragmentReciever(1)
    header = {'tcp_packet_length': 11, 'dest_host': 'example.com', 'dest_port': 80}
    r.recieve_fragment(ICMPPacket(type=8, code=0, id=1, seq_num=0, payload=pickle.dumps(header)))
    r.recieve_fragment(ICMPPacket(type=8, code=0, id=1, seq_num=1, payload=b'Hello '))
    r.recieve_fragment(ICMPPacket(type=8, code=0, id=1, seq_num=2, payload=b'World'))
    assert r.is_complete()
    data, host, port = r.reconstruct_tcp_data()
    assert data == b'Hello World'
    assert host == 'example.com'
    assert port == 80


def test_reconstruct_incomplete():
    r = ICMTCPFragmentReciever(1)
    header = {'tcp_packet_length': 10, 'dest_host': 'example.com', 'dest_port': 80}
    r.recieve_fragment(ICMPPacket(type=8, code=0, id=1, seq_num=0, payload=pickle.dumps(header)))
    r.recieve_fragment(ICMPPacket(type=8, code=0, id=1, seq_num=1, payload=b'Partial'))
    with pytest.raises(ValueError):
        r.reconstruct_tcp_data()
