from .logger import Logger
import socket
from .icmtcp_fragment_reciever import ICMTCPFragmentReciever
from .icmp_packet import ICMPPacket, ICMP_PACKET_SIZE, ICMP_ECHO_REPLY_TYPE, ICMP_ECHO_REPLY_CODE, ICMP_ECHO_REQUEST_TYPE
from datetime import datetime
import threading
from .icmtcp_fragmentor import fragment

logger = Logger(__name__)

RETRANSMIT_TIMEOUT = 5
IP_HEADER_SIZE = 20

class ICMTCPTunnel:
    def __init__(self, tunnel_ip):
        self.tunnel_ip = tunnel_ip
        self.icmp_socket = self.create_icmp_socket()
        self.pending_fragment_confirmations = {}
        self.fragment_recievers = {}
        self.recieved_tcp_packets = []
        self.fragment_id = 0

    @staticmethod
    def create_icmp_socket():
        """
        @brief Create a raw ICMP socket
        @returns: ICMP socket
        """
        try:
            icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            logger.info("ICMP socket created successfully")

        except Exception as e:
            logger.error(f"Failed to create ICMP socket: {e}")
            raise e
        
        return icmp_socket
    
    def send_confirmation(self, icmp_packet: ICMPPacket):
        """
        @brief Send a confirmation ICMP packet for the received fragment
        @param icmp_packet The received ICMP packet to confirm
        """
        try:
            confirmation_packet = ICMPPacket(
                type=ICMP_ECHO_REPLY_TYPE,
                code=ICMP_ECHO_REPLY_CODE,
                id=icmp_packet.id,
                seq_num=icmp_packet.seq_num
            )
            self.icmp_socket.sendto(confirmation_packet.raw_packet(), (self.tunnel_ip, 0))
            logger.info(f"Sent confirmation for ICMP packet ID {icmp_packet.id} Seq {icmp_packet.seq_num}")

        except Exception as e:
            logger.error(f"Failed to send confirmation ICMP packet: {e}")
            raise e
    
    def recieve_packet(self, packet: ICMPPacket):
        """
        @brief Handle a received ICMP packet
        @param raw_data The raw bytes of the received ICMP packet
        """
        logger.info(f"Received ICMP packet ID {packet.id} Seq {packet.seq_num}")
        if packet.id not in self.fragment_recievers:
            self.fragment_recievers[packet.id] = ICMTCPFragmentReciever(packet.id)

        handler = self.fragment_recievers[packet.id]

        try:
            handler.recieve_fragment(packet)

        except Exception as e:
            logger.error(f"Error processing fragment: {e}")
            return
    
        self.send_confirmation(packet)

        if handler.is_complete():
            self.complete_fragment(packet.id)
            

    def complete_fragment(self, id):
        """
        @brief Handle the completion of fragment reception for a given ID 
            and add complete TCP data to tcp queue
        @param id The ID of the fragment set to complete
        """
        handler = self.fragment_recievers.get(id)
        try:
            tcp_data, dest_host, dest_port = handler.reconstruct_tcp_data()
            self.recieved_tcp_packets.append((tcp_data, dest_host, dest_port))
            logger.info(f"Successfully reconstructed TCP data for ID {id}")

        except Exception as e:
            logger.error(f"Failed to reconstruct TCP data for ID {id}: {e}")
                
        del self.fragment_recievers[id]
    
    def packet_recieve_worker(self):
        """
        @brief Worker function to receive ICMP packets
        """
        while True:
            raw_data, addr = self.icmp_socket.recvfrom(ICMP_PACKET_SIZE)
            packet = ICMPPacket()
            try:
                packet.from_bytes(raw_data[IP_HEADER_SIZE:])

            except Exception as e:
                logger.error(f"Failed to parse ICMP packet: {e}")
                continue

            if packet.type == ICMP_ECHO_REPLY_TYPE:
                self.confirm_packet(packet)

            elif packet.type == ICMP_ECHO_REQUEST_TYPE:
                self.recieve_packet(packet)

            else:
                logger.warning(f"Received ICMP packet with unsupported type {packet.type}")
                logger.debug(f"type: {packet.type}, code: {packet.code}, id: {packet.id}, seq: {packet.seq_num}, payload: {packet.payload}")

    def confirm_packet(self, packet: ICMPPacket):
        """
        @brief Handle confirmation of sent ICMP packet
        @param packet The confirmed ICMP packet
        """
        key = (packet.id, packet.seq_num)
        if key in self.pending_fragment_confirmations:
            del self.pending_fragment_confirmations[key]
            logger.info(f"Confirmed receipt of ICMP packet ID {packet.id} Seq {packet.seq_num}")
        else:
            logger.warning(f"Received confirmation for unknown ICMP packet ID {packet.id} Seq {packet.seq_num}")

    def send_icmp_packet(self, icmp_packet: ICMPPacket):
        """
        @brief Send an ICMP packet through the tunnel
        @param icmp_packet The ICMP packet to send
        """
        try:
            logger.debug(f"Sending ICMP packet: id {icmp_packet.id} Seq {icmp_packet.seq_num}")
            self.icmp_socket.sendto(icmp_packet.raw_packet(), (self.tunnel_ip, 0))
            logger.info(f"Sent ICMP packet to {self.tunnel_ip} with ID {icmp_packet.id} and Seq {icmp_packet.seq_num}")

        except Exception as e:
            logger.error(f"Failed to send ICMP packet: {e}")
            raise e
        
        self.add_to_confirmation_list(icmp_packet)
        
    def add_to_confirmation_list(self, icmp_packet: ICMPPacket):
        """
        @brief Add an ICMP packet to the pending confirmation list
        @param icmp_packet The ICMP packet to track for confirmation
        """
        self.pending_fragment_confirmations[(icmp_packet.id, icmp_packet.seq_num)] = (icmp_packet, datetime.now())

    def retransmit_worker(self):
        """
        @brief Worker function to retransmit unconfirmed ICMP packets
        """
        while True:
            now = datetime.now()
            to_retransmit = []
            for key, (packet, timestamp) in list(self.pending_fragment_confirmations.items()):
                if (now - timestamp).total_seconds() > RETRANSMIT_TIMEOUT:
                    to_retransmit.append(packet)
                    del self.pending_fragment_confirmations[key]
            
            for packet in to_retransmit:
                logger.info(f"Retransmitting ICMP packet ID {packet.id} Seq {packet.seq_num}")
                logger.debug(f"Raw data: {packet.raw_packet()}")
                self.send_icmp_packet(packet)

    def send_tcp_data(self, tcp_data, dest_host, dest_port):
        """
        @brief Fragment and send TCP data over ICMP
        @param tcp_data The raw TCP data to send
        """
        icmp_fragments = fragment(tcp_data, self.fragment_id, dest_host, dest_port)
        logger.info(f"Fragmented TCP data into {len(icmp_fragments)} ICMP packets with ID {self.fragment_id}")
        self.fragment_id += 1
        for icmp_packet in icmp_fragments:
            self.send_icmp_packet(icmp_packet)

    def run(self):
        """
        @brief Start the ICMTCP tunnel
        """
        recieve_thread = threading.Thread(target=self.packet_recieve_worker, daemon=True)
        retransmit_thread = threading.Thread(target=self.retransmit_worker, daemon=True)

        recieve_thread.start()
        retransmit_thread.start()

        logger.info("ICMTCP Tunnel is running")

    def close(self):
        """
        @brief Close the ICMTCP tunnel
        """
        self.icmp_socket.close()
        logger.info("ICMTCP Tunnel closed")
            
            
