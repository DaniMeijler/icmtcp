import socket
import time
import pytest
import subprocess, os


@pytest.fixture(scope="module")
def socat_forwarders():
    """
    sets up socat listeners that forward traffic to the icmtcp_client instances.
    - localhost:8080 -> client:1704 (for 95.85.16.212)
    - localhost:8081 -> client:1705 (for 1.1.1.1)
    """
    procs = []
    commands = [
        "socat TCP4-LISTEN:8080,fork,reuseaddr TCP4:127.0.0.1:1704",
        "socat TCP4-LISTEN:8081,fork,reuseaddr TCP4:127.0.0.1:1705"
    ]
    for cmd in commands:
        proc = subprocess.Popen(cmd, shell=True, preexec_fn=os.setsid)
        procs.append(proc)
    
    time.sleep(1) 
    yield
    for proc in procs:
        os.killpg(os.getpgid(proc.pid), subprocess.signal.SIGTERM)


def test_basic_connection(socat_forwarders):
    """Tests a basic HTTP GET request through the tunnel."""
    tunneled_command = "curl -s -i http://127.0.0.1:8080/ -H 'Host: 95.85.16.212'"
    tunnel_result = subprocess.check_output(tunneled_command, shell=True, text=True)
    
    command = "curl -s -i http://95.85.16.212/"
    regular_result = subprocess.check_output(command, shell=True, text=True)
    
    assert "HTTP/1.1 200 OK" in tunnel_result.splitlines()[0]
    assert tunnel_result.splitlines()[0] == regular_result.splitlines()[0]


def test_multiple_requests(socat_forwarders):
    """Tests that multiple sequential requests on the same port work correctly."""
    tunneled_command = "curl -s -i http://127.0.0.1:8080/ -H 'Host: 95.85.16.212'"
    for _ in range(3):
        tunnel_result = subprocess.check_output(tunneled_command, shell=True, text=True)
        assert "HTTP/1.1 200 OK" in tunnel_result


def test_client_connection_timeout():
    """Ensures the client closes an inactive socket after its timeout."""
    client_timeout = 4 
    
    s = socket.create_connection(('127.0.0.1', 1704), timeout=2)
    print(f"Socket connected. Waiting for {client_timeout + 1} seconds to trigger timeout...")
    time.sleep(client_timeout + 1)
    
    try:
        s.sendall(b'ping')
        data = s.recv(1024)
        assert data == b'', "Connection should have been closed by the client, but it's still open."
    except (ConnectionResetError, BrokenPipeError):
        assert True
    except Exception as e:
        pytest.fail(f"Expected a connection error, but got {type(e).__name__}: {e}")
    finally:
        s.close()


def test_large_data_transfer(socat_forwarders):
    """Tests fragmentation by sending a large payload."""
    large_payload = b'X' * 20000 

    post_command = (
        f"curl -s -i -X POST --data-binary @- http://127.0.0.1:8080/ "
        f"-H 'Host: 95.85.16.212' -H 'Content-Type: text/plain' -H 'Content-Length: {len(large_payload)}'"
    )
    
    process = subprocess.Popen(post_command, shell=True, text=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    stdout, _ = process.communicate(input=large_payload.decode())
    
    assert "HTTP/1.1" in stdout


def test_multiple_parallel_streams(socat_forwarders):
    """Tests that two client instances can run in parallel, tunneling to different destinations."""
    tunneled_command_1 = "curl -s -i http://127.0.0.1:8080/ -H 'Host: 95.85.16.212'"
    tunneled_command_2 = "curl -s -i http://127.0.0.1:8081/ -H 'Host: 1.1.1.1'"
    
    tunnel_result_1 = subprocess.check_output(tunneled_command_1, shell=True, text=True)
    tunnel_result_2 = subprocess.check_output(tunneled_command_2, shell=True, text=True)
    
    command_1 = "curl -s -i http://95.85.16.212/"
    command_2 = "curl -s -i http://1.1.1.1"
    result_1 = subprocess.check_output(command_1, shell=True, text=True)
    result_2 = subprocess.check_output(command_2, shell=True, text=True)
    
    assert result_1.splitlines()[0] == tunnel_result_1.splitlines()[0]
    assert result_2.splitlines()[0] == tunnel_result_2.splitlines()[0]
