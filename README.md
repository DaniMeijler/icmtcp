# ICMTCP3

ICMTCP is a tool for tunneling TCP over ICMP. This tool requires two hosts to work.

Client:
    Runs icmtcp_client.py. Opens up a local tcp port on host that forwards all accepted packets to icmp tunnel.
    Can be used to forward data from adjacent host or from self.

Server:
    Runs icmtcp_server.py. 
    The server listens for ICMP-encapsulated TCP data from a client/tunnel and forwards it to the destination TCP host:port by creating outbound TCP connections.
    Uses multhithreading to communicate with several destinations if needed.


## Running the client

```bash
sudo python3 icmtcp_client.py -t <tunnel_ip> -d <dest_ip> -p <dest_port>
```

Example - send to tunnel at ip 1.2.3.4 and ultimately to 8.8.8.8:80:
```bash
sudo python3 icmtcp_client.py -t 1.2.3.4 -d 8.8.8.8 -p 80
```

### Run the server


```bash
cd /path/to/icmtcp3/src
sudo python3 icmtcp_server.py -t <client_tunnel_ip>
```

Example - run a server that expects the client at 1.2.3.5:

```bash
sudo python3 icmtcp_server.py -t 1.2.3.5
```

## Shutdown / behavior

- The client and server start worker threads for accepting/forwarding TCP data and for running the ICMP tunnel loop.
- Use Ctrl+C (KeyboardInterrupt) to stop either process. This should trigger a clean exit: sockets are closed and worker loops exit cleanly.

## Notes

- Running raw ICMP sockets typically requires root privileges. `sudo` is expected.
- Requires no external python libraries to run.

