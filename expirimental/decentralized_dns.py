from typing import Dict, Optional
from network_node import NetworkNode
from concensus_network import ConsensusNetwork
import ipaddress
import aioquic
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection

class DecentralizedDNS:
    def __init__(self, network: ConsensusNetwork):
        self.network = network
        self.dns_records: Dict[str, Dict] = {}
        
        # Initialize QUIC for DNS-over-QUIC
        self.quic_configuration = QuicConfiguration(
            is_client=True,
            alpn_protocols=["dns-over-quic"]
        )
        
    async def add_record(self, domain: str, record_type: str, value: str, 
                        requesting_node: NetworkNode):
        # Validate IPv6 address if it's an AAAA record
        if record_type == "AAAA":
            try:
                ipaddress.IPv6Address(value)
            except ipaddress.AddressValueError:
                raise ValueError("Invalid IPv6 address")
        
        if self.network.validate_certificate_request(
            requesting_node.create_certificate_request(domain), 
            requesting_node
        ):
            self.dns_records[domain] = {
                "type": record_type,
                "value": value,
                "certificate": self.network.issue_certificate(
                    requesting_node.create_certificate_request(domain),
                    domain
                )
            }
            
    async def resolve(self, domain: str) -> Optional[Dict]:
        # Implement DNS-over-QUIC resolution
        record = self.dns_records.get(domain)
        if record and record["type"] == "AAAA":
            # Verify IPv6 address is still valid
            try:
                ipaddress.IPv6Address(record["value"])
                return record
            except ipaddress.AddressValueError:
                return None
        return record