from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from typing import Dict
import aioquic
import falcon
import ipaddress

class NetworkNode:
    def __init__(self, node_id: str, is_consensus_authority: bool = False):
        # Generate node's Falcon key pair (post-quantum)
        self.private_key = falcon.generate_private_key(
            mode="Falcon-1024"
        )
        self.public_key = self.private_key.public_key()
        self.node_id = node_id
        self.is_consensus_authority = is_consensus_authority
        self.dns_records: Dict[str, Dict] = {}
        self.issued_certificates: Dict[str, x509.Certificate] = {}
        
        # Initialize QUIC transport
        self.quic_configuration = aioquic.QuicConfiguration(
            is_client=False,
            alpn_protocols=["dns-over-quic"]
        )
        
    def create_certificate_request(self, domain: str) -> x509.CertificateSigningRequest:
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, domain),
        ]))
        
        # Add IPv6 support in SAN
        builder = builder.add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(domain),
                x509.IPAddress(ipaddress.IPv6Address('2001:db8::1'))
            ]),
            critical=False
        )
        
        request = builder.sign(
            self.private_key,
            hashes.SHAKE256()
        )
        return request


