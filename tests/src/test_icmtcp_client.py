import pytest
from unittest.mock import Mock, patch, MagicMock, call
import socket

from icmtcp_client import ICMTCPClient, TCP_PACKET_SIZE

@pytest.fixture
def mock_tunnel():
    """Fixture for a mocked ICMTCPTunnel."""
    return MagicMock()

@pytest.fixture
def client(mock_tunnel):
    """Fixture to create an ICMTCPClient instance with mocked dependencies."""
    with patch('icmtcp_client.socket.socket'), \
         patch('icmtcp_client.ICMTCPTunnel', return_value=mock_tunnel):
        client_instance = ICMTCPClient(
            tunnel_ip='1.2.3.4',
            dest_address='95.85.16.212',
            dest_port=80
        )
        client_instance.connection_lock = MagicMock()
        return client_instance

def test_client_init(client, mock_tunnel):
    """Tests that the client initializes correctly."""
    assert client.icmp_tunnel == mock_tunnel
    assert client.client_tcp_connection is None

def test_handle_tcp_connection_accepts_first_client(client, mock_tunnel):
    """Tests that the first incoming TCP connection is accepted and handled."""
    mock_socket = MagicMock()
    mock_socket.recv.side_effect = [b'test_data', b'']
    client_address = ('127.0.0.1', 54321)

    client.handle_tcp_connection(mock_socket, client_address)

    assert client.client_tcp_connection is None
    client.connection_lock.__enter__.assert_called()
    mock_tunnel.send_tcp_data.assert_called_once_with(b'test_data', client.dest_address, client.dest_port)
    mock_socket.close.assert_called_once()

def test_handle_tcp_connection_rejects_second_client(client):
    """Tests that a second TCP connection is rejected if one is already active."""
    client.client_tcp_connection = MagicMock()
    
    new_mock_socket = MagicMock()
    new_client_address = ('127.0.0.1', 12345)

    client.handle_tcp_connection(new_mock_socket, new_client_address)

    new_mock_socket.close.assert_called_once()
    new_mock_socket.recv.assert_not_called()

@patch('icmtcp_client.threading.Thread')
def test_tcp_to_tunnel_worker_accepts_connections(mock_thread, client):
    """Tests that the listening worker accepts connections and starts handler threads."""
    mock_server_socket = MagicMock()
    client.tcp_server_socket = mock_server_socket
    
    mock_client_socket = MagicMock()
    client_address = ('127.0.0.1', 54321)
    mock_server_socket.accept.return_value = (mock_client_socket, client_address)

    client.tcp_to_tunnel_worker()

    mock_server_socket.listen.assert_called_once_with(5)
    mock_server_socket.accept.assert_called_once()
    mock_client_socket.settimeout.assert_called_once_with(client.client_timeout)
    mock_thread.assert_called_once_with(
        target=client.handle_tcp_connection,
        args=(mock_client_socket, client_address),
        daemon=True
    )
    mock_thread.return_value.start.assert_called_once()

def test_tunnel_to_tcp_worker_forwards_to_client(client):
    """Tests that data from the tunnel is forwarded to the active TCP client."""
    test_data = b'response_data'
    client.icmp_tunnel.recieved_tcp_packets = [(test_data, 'host', 80)]
    
    mock_client_socket = MagicMock()
    client.client_tcp_connection = mock_client_socket

    client.tunnel_to_tcp_worker()

    mock_client_socket.sendall.assert_called_once_with(test_data)

def test_close_client(client, mock_tunnel):
    """Tests that the client closes all its resources."""
    mock_server_socket = MagicMock()
    mock_client_conn = MagicMock()
    client.tcp_server_socket = mock_server_socket
    client.client_tcp_connection = mock_client_conn

    client.close()

    mock_server_socket.close.assert_called_once()
    mock_client_conn.close.assert_called_once()
    mock_tunnel.close.assert_called_once()
