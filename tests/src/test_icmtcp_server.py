import pytest
from unittest.mock import Mock, patch, MagicMock, call
import socket
import select
import threading
import time


from src.icmtcp_server import ICMTCPServer, TCP_PACKET_SIZE

@pytest.fixture
def mock_tunnel():
    """Fixture for a mocked ICMTCPTunnel."""
    return MagicMock()

@pytest.fixture
def server(mock_tunnel):
    """Fixture to create an ICMTCPServer instance with a mocked tunnel."""
    with patch('icmtcp_server.ICMTCPTunnel', return_value=mock_tunnel):
        server_instance = ICMTCPServer(tunnel_ip='1.2.3.5')
        server_instance.connections_lock = MagicMock(wraps=threading.Lock())
        return server_instance

@patch('icmtcp_server.socket.socket')
def test_get_or_create_socket_creates_new(mock_socket_constructor, server):
    """Tests that a new socket is created if one doesn't exist."""
    mock_socket = MagicMock()
    mock_socket_constructor.return_value = mock_socket
    dest_host, dest_port = '8.8.8.8', 80

    created_socket = server._get_or_create_socket(dest_host, dest_port)

    assert created_socket == mock_socket
    mock_socket.connect.assert_called_once_with((dest_host, dest_port))
    assert server.active_tcp_connections[(dest_host, dest_port)] == mock_socket
    server.connections_lock.__enter__.assert_called()

def test_get_or_create_socket_returns_existing(server):
    """Tests that an existing socket is returned if available."""
    dest_host, dest_port = '8.8.8.8', 80
    existing_socket = MagicMock()
    server.active_tcp_connections[(dest_host, dest_port)] = existing_socket

    returned_socket = server._get_or_create_socket(dest_host, dest_port)

    assert returned_socket == existing_socket
    server.connections_lock.__enter__.assert_called()

def test_tunnel_to_tcp_worker_sends_data(server):
    """Tests that data from the tunnel is sent to the correct TCP socket."""
    dest_host, dest_port = '8.8.8.8', 80
    test_data = b'test_payload'
    server.icmp_tunnel.recieved_tcp_packets = [(test_data, dest_host, dest_port)]

    mock_socket = MagicMock()
    server._get_or_create_socket = MagicMock(return_value=mock_socket)
    server._try_send_with_reconnect = MagicMock(return_value=True)

    worker_thread = threading.Thread(target=server.tunnel_to_tcp_worker, daemon=True)
    worker_thread.start()
    time.sleep(5)
    server._get_or_create_socket.assert_called_once_with(dest_host, dest_port)
    server._try_send_with_reconnect.assert_called_once_with(mock_socket, test_data, dest_host, dest_port)

@patch('icmtcp_server.select.select')
def test_tcp_to_tunnel_worker_forwards_data(mock_select, server, mock_tunnel):
    """Tests that data received from a TCP socket is forwarded to the tunnel."""
    dest_host, dest_port = '8.8.8.8', 80
    test_data = b'response_payload'
    
    mock_socket = MagicMock()
    mock_socket.recv.return_value = test_data
    with server.connections_lock:
        server.active_tcp_connections[(dest_host, dest_port)] = mock_socket

    class StopTestLoop(Exception):
        pass

    mock_select.side_effect = [
        ([mock_socket], [], []),
        StopTestLoop
    ]

    with pytest.raises(StopTestLoop):
        server.tcp_to_tunnel_worker()
    mock_socket.recv.assert_called_once_with(TCP_PACKET_SIZE)
    mock_tunnel.send_tcp_data.assert_called_once_with(test_data, dest_host, dest_port)

@patch('icmtcp_server.select.select')
def test_tcp_to_tunnel_worker_handles_closed_socket(mock_select, server):
    """Tests that the worker correctly handles a remotely closed socket."""
    dest_host, dest_port = '8.8.8.8', 80
    
    mock_socket = MagicMock()
    mock_socket.recv.return_value = b''
    server.active_tcp_connections[(dest_host, dest_port)] = mock_socket
    
    mock_select.return_value = ([mock_socket], [], [])
    server.remove_closed_connection = MagicMock()

    worker_thread = threading.Thread(target=server.tcp_to_tunnel_worker, daemon=True)
    worker_thread.start()
    time.sleep(5)

    server.remove_closed_connection.assert_called_with(mock_socket)