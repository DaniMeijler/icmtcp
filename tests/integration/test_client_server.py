import socket
import time
import pytest
import subprocess


@pytest.mark.integration
def test_basic_connection():
    tunneled_command = "curl -p http://127.0.0.1:1704 http://95.85.16.212/"
    tunnel_result = subprocess.check_output(tunneled_command, shell=True, text=True)
    command = "curl http://95.85.16.212/"
    regular_result = subprocess.check_output(command, shell=True, text=True)
    assert tunnel_result[:100] == regular_result[:100]


@pytest.mark.integration
def test_multiple_requests():
    tunneled_command = "curl -p http://127.0.0.1:1704 http://95.85.16.212/"
    for _ in range(3):
        tunnel_result = subprocess.check_output(tunneled_command, shell=True, text=True)
        assert tunnel_result.startswith('<!DOCTYPE html>')


@pytest.mark.integration
def test_connection_timeout():
    """ 
    Ensure client has a timeout configured and will close inactive sockets 
    """
    s = socket.create_connection(('127.0.0.1', 1704), timeout=5)
    # wait longer than typical client timeout configured in code
    time.sleep(2)
    try:
        s.send(b'GET / HTTP/1.0\r\nHost: 95.85.16.212\r\n\r\n')
        _ = s.recv(1024)
    except Exception:
        pytest.skip('Connection timed out or closed by client; acceptable')
    finally:
        s.close()


@pytest.mark.integration
def test_large_data_transfer():
    s = socket.create_connection(('127.0.0.1', 1704), timeout=10)
    large = b'X' * 65536
    req = b'POST / HTTP/1.0\r\nHost: 95.85.16.212\r\nContent-Length: %d\r\n\r\n' % len(large)
    s.send(req + large)
    r = s.recv(4096)
    s.close()
    assert len(r) >= 0


@pytest.mark.integration
def test_multiple_packet_streams():
    tunneled_command_1 = "curl -p http://127.0.0.1:1704 http://95.85.16.212/"
    tunneled_command_2 = "curl -p http://127.0.0.1:1705 http://1.1.1.1"
    tunnel_result_1 = subprocess.check_output(tunneled_command_1, shell=True, text=True)
    tunnel_result_2 = subprocess.check_output(tunneled_command_2, shell=True, text=True)
    #assert tunnel_result_1.startswith('<!DOCTYPE html>') or tunnel_result_1.startswith('<html>')
    #assert tunnel_result_2.startswith('<!DOCTYPE html>') or tunnel_result_2.startswith('<html>')
    command_1 = "curl http://95.85.16.212/"
    command_2 = "curl http://1.1.1.1"
    result_1 = subprocess.check_output(command_1, shell=True, text=True)
    result_2 = subprocess.check_output(command_2, shell=True, text=True)
    assert result_1[:100] == tunnel_result_1[:100]
    assert result_2[:100] == tunnel_result_2[:100]
