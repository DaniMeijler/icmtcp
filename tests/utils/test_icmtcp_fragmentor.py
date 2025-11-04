import pickle
from src.utils.icmtcp_fragmentor import fragment, create_header_fragment
from src.utils.icmp_packet import ICMP_PAYLOAD_MAX_SIZE


def test_create_header_fragment():
    pkt = create_header_fragment(b'Hello', 'example.com', 80, 1)
    assert pkt.seq_num == 0
    meta = pickle.loads(pkt.payload)
    assert meta['tcp_packet_length'] == 5
    assert meta['dest_host'] == 'example.com'
    assert meta['dest_port'] == 80


def test_fragment_small_payload():
    data = b'Small'
    frags = fragment(data, 1, 'example.com', 80)
    assert len(frags) == 2
    assert frags[1].payload == data


def test_fragment_large_payload():
    data = b'X' * (ICMP_PAYLOAD_MAX_SIZE + 100)
    frags = fragment(data, 2, 'example.com', 80)
    expected = 1 + ((len(data) + ICMP_PAYLOAD_MAX_SIZE - 1) // ICMP_PAYLOAD_MAX_SIZE)
    assert len(frags) == expected
    recon = b''.join([f.payload for f in frags[1:]])
    assert recon == data


def test_fragment_empty_payload():
    data = b''
    frags = fragment(data, 3, 'example.com', 80)
    assert len(frags) == 1


def test_fragment_sequence_numbering():
    data = b'X' * (ICMP_PAYLOAD_MAX_SIZE * 3)
    frags = fragment(data, 4, 'example.com', 80)
    assert frags[0].seq_num == 0
    for i, f in enumerate(frags[1:], 1):
        assert f.seq_num == i


def test_fragment_max_size_boundary():
    data = b'X' * ICMP_PAYLOAD_MAX_SIZE
    frags = fragment(data, 5, 'example.com', 80)
    assert len(frags) == 2
    data2 = b'X' * (ICMP_PAYLOAD_MAX_SIZE + 1)
    frags2 = fragment(data2, 6, 'example.com', 80)
    assert len(frags2) == 3
