# NEXUS Network Suite

## Overview
NEXUS is a DNS-over-QUIC protocol implementation with post-quantum cryptography, designed for secure, scalable distributed DNS. It features Falcon-1024 quantum-resistant signatures and supports both local TLD management and external DNS resolution.

### Key Features
- **DNS-over-QUIC**: Secure, fast DNS resolution using QUIC transport
- **Post-Quantum Security**: Falcon-1024 cryptography for quantum-resistant certificates
- **Multi-Network Support**: Simultaneous private, public, and federated networks
- **Comprehensive DNS Records**: A, AAAA, MX, TXT, SRV, CNAME, PTR support
- **External DNS Integration**: Automatic fallback to external DNS servers
- **IPv6 Native**: Full IPv6 support throughout the system

## Quick Start

### Building
```bash
git clone https://github.com/vaziolabs/nexus.git
cd nexus
make clean && make
```

### Running
```bash
# Start a private network
./build/nexus --mode private --hostname test.local

# Use the CLI
./build/nexus_cli status
./build/nexus_cli lookup example.com
```

### Testing
```bash
# Run all tests
make test

# Run integration tests
./tests/integration_falcon_test.sh
```

## Current Status (December 2024)

### ✅ Working Features
- **Compilation**: Project builds successfully
- **Core Infrastructure**: CA, CT, network context, CLI operational
- **Test Suite**: All unit tests passing
- **Falcon Cryptography**: Fully implemented with Falcon-1024
- **DNS Resolution**: Complete support for all major record types
- **External DNS**: Recursive resolution with fallback servers
- **Memory Management**: Stable cleanup and error handling
- **IPv6 Support**: Native IPv6 throughout the system

### 🔄 In Progress
- **Client Connections**: SSL/QUIC handshake issues being resolved
- **Performance Optimization**: Caching and connection pooling
- **TLD Mirroring**: Peer-to-peer synchronization

### 🎯 Planned Features
- **Web3 Integration**: Blockchain-based domain registration
- **Global Deployment**: dns.hypermesh.online service
- **Advanced Security**: DNSSEC and zero-knowledge proofs

## Architecture

NEXUS operates in three modes:
- **Private**: Local TLD management for internal networks
- **Public**: Connect to global NEXUS networks
- **Federated**: Peer-to-peer network with selective sharing

### Multi-Network Support
Run multiple isolated networks simultaneously with independent:
- Certificate authorities and trust chains
- DNS records and resolution paths
- Security policies and access controls
- Performance and configuration settings

## Configuration

### Basic Configuration
```bash
# Create default configuration
./build/nexus_cli configure

# Start with custom settings
./build/nexus --mode private --hostname mynode.local
```

### Profile Management
```bash
# List profiles
./build/nexus_cli list-profiles

# Create new profile
./build/nexus_cli add-profile work federated

# Start specific profile
./build/nexus_cli start work
```

## DNS Operations

### TLD Management
```bash
# Register a TLD
./build/nexus_cli register-tld home example

# Add DNS records
./build/nexus_cli add-record home example server AAAA 2001:db8::1
```

### DNS Resolution
```bash
# Resolve local domains
./build/nexus_cli lookup server.example

# External domains automatically resolved
./build/nexus_cli lookup google.com
```

## Development

### Project Structure
- `src/`: Core implementation
- `include/`: Headers and external libraries
- `tests/`: Unit and integration tests
- `utils/`: Helper scripts and tools

### Key Components
- **Certificate Authority**: Falcon-based CA with quantum-resistant certificates
- **DNS Resolver**: Multi-record type resolver with external DNS fallback
- **QUIC Transport**: ngtcp2-based secure transport layer
- **Network Context**: Multi-network isolation and management

### Testing
```bash
# Unit tests
make test

# Specific component tests
make test_ca test_dns test_tld

# Integration tests
./tests/integration_falcon_test.sh
./tests/run_ipv6_falcon_test.sh
```

## Falcon Post-Quantum Cryptography

NEXUS integrates Falcon-1024 signatures for quantum-resistant security:
- Certificate generation and validation
- Certificate Transparency logs
- TLS handshake verification
- DNS record authentication

## Contributing

1. Fork the repository
2. Create a feature branch
3. Run tests: `make test`
4. Submit a pull request

## License

Licensed under the MIT License. See LICENSE file for details.

## Vision: Web3 DNS Service

NEXUS aims to power **dns.hypermesh.online**, a global Web3 DNS service featuring:
- Direct TLD registration (e.g., "nike", "nascar")
- Blockchain-backed domain ownership
- HTTP/3 optimization
- Global distribution with high availability

---

*NEXUS: Secure, Scalable, Quantum-Resistant DNS for the Future*
