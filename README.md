# NEXUS Network Suite

## Overview
NEXUS is a simple, secure, scalable DNS-over-QUIC protocol implementation designed for the hypermesh network, providing enhanced security, performance, and scalability features for distributed DNS. Beyond DNS, NEXUS is designed to evolve into a comprehensive network protocol replacement leveraging QUIC's capabilities to handle tunneling, IPv6 allocation, and NAT traversal. NEXUS now integrates Falcon post-quantum cryptography for certificate operations, providing quantum-resistant security for the entire certificate infrastructure.

## Current Status

### May 2025 Update
NEXUS has undergone significant stability improvements:
- Fixed compatibility issues with different versions of the ngtcp2 library
- Improved error handling in critical network components
- Enhanced certificate management for more reliable QUIC handshakes
- Fixed server initialization issues identified during testing
- Addressed compiler warnings and memory safety issues
- Improved test framework with comprehensive integration tests

All core components are now stable and passing tests. The project is ready for further feature development focused on advanced DNS resolution, TLD mirroring, and tunneling infrastructure.

## Quick Start Guide

### 1. Building NEXUS

Clone the repository and build the binaries:

```bash
git clone https://github.com/vaziolabs/nexus.git
cd nexus
make clean && make
```

This builds both the NEXUS daemon (`build/nexus`) and the CLI tool (`build/nexus_cli`).

### 2. Setting Up NEXUS

#### Initial Configuration

Run the configuration wizard to create a basic configuration:

```bash
./build/nexus_cli configure
```

This creates a default configuration with a private mode profile in `~/.config/nexus/config.json`.

#### Manual Configuration

You can also create configuration files manually in `~/.config/nexus/profiles/` for more control.

Example profile configuration file (`~/.config/nexus/profiles/home.json`):
```json
{
  "name": "home",
  "mode": "private",
  "hostname": "home.local",
  "server": "home.local",
  "server_port": 10053,
  "client_port": 10443,
  "ipv6_prefix": "fd00:1234:5678::",
  "ipv6_prefix_length": 64,
  "max_tunnels": 10,
  "auto_connect": true,
  "enable_nat_traversal": true,
  "enable_relay": false,
  "enable_ct": true
}
```

### 3. Running NEXUS

#### Starting the Daemon

Start NEXUS with a specific profile:

```bash
./build/nexus --profile home
```

Or run it with direct parameters:

```bash
./build/nexus --mode private --hostname home.local --server home.local
```

#### Running as a Service

To run NEXUS as a background service:

```bash
./build/nexus --service
```

This will load the default profile or all profiles with `auto_connect` set to true.

#### Systemd Integration (Linux)

Create a systemd service file `/etc/systemd/system/nexus.service`:

```
[Unit]
Description=NEXUS Network Service
After=network.target

[Service]
Type=simple
ExecStart=/path/to/nexus/build/nexus --service
Restart=on-failure
User=nexus

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl enable nexus
sudo systemctl start nexus
```

### 4. Using the CLI

The CLI tool interacts with the running daemon to perform various operations.

#### Basic Commands

Check service status:
```bash
./build/nexus_cli status
```

List available profiles:
```bash
./build/nexus_cli list-profiles
```

Show details of a profile:
```bash
./build/nexus_cli show-profile home
```

#### Network Management

Start a profile:
```bash
./build/nexus_cli start home
```

Stop a profile:
```bash
./build/nexus_cli stop home
```

Restart a profile:
```bash
./build/nexus_cli restart home
```

#### Domain Management

Register a new TLD:
```bash
./build/nexus_cli register-tld home example
```

This registers the TLD "example" using the "home" profile, allowing you to resolve names like "server.example".

#### DNS Lookups

Look up a hostname:
```bash
./build/nexus_cli lookup server.example
```

### 5. Multi-Network Configuration

NEXUS supports simultaneous connections to different networks. You can create and manage multiple profiles:

```bash
# Create a profile for work network
./build/nexus_cli add-profile work federated

# Configure the work profile
./build/nexus_cli edit-profile work hostname workstation
./build/nexus_cli edit-profile work server nexus.company.com

# Start both networks
./build/nexus_cli start home
./build/nexus_cli start work
```

### 6. Monitoring and Troubleshooting

#### Check Service Logs

```bash
# If running as a systemd service
sudo journalctl -u nexus -f

# Check configuration files
ls -la ~/.config/nexus/
```

## Implementation Status

### Completed Components
- [x] **Configuration Management System** - Auto-detection of network settings and profile management
- [x] **Multi-Network Architecture** - Support for running multiple isolated networks simultaneously
- [x] **CLI Interface** - Command-line tools for managing the NEXUS service and network profiles
- [x] **Certificate Transparency** - Federated scope-based CT logs with Merkle tree verification
- [x] **Service Architecture** - Daemon mode with proper service lifecycle management
- [x] **Basic Core DNS Functionality** - DNS request/response handling and TLD management (local resolution of AAAA records)
- [x] **QUIC Transport Integration** - Utilizes ngtcp2 for secure and reliable transport
- [x] **Falcon Post-Quantum Cryptography** - Integration of Falcon signatures for certificate operations, including CA infrastructure and certificate verification during QUIC handshake
- [x] **Test Framework Fixes** - Resolved issues with multiple main function definitions in test files
- [x] **Code Quality Improvements** - Addressed compiler warnings and potential memory safety issues
- [x] **Server Initialization** - Fixed server startup issues identified during testing
- [x] **QUIC Handshake** - Improved handshake reliability with better error handling and certificate management


### In Progress Components
- [ ] **Advanced DNS Resolution Features** - Implementation of recursive/iterative resolution, broader record type support (CNAME, MX, TXT, SRV, etc.), and resolver logic.
- [ ] **TLD Mirroring** - Robust synchronization with automatic conflict resolution
- [ ] **Peer Discovery** - Automatic network topology mapping
- [ ] **Metrics Collection** - Performance monitoring and optimization
- [ ] **Tunneling Infrastructure** - Implementation of per-tunnel IPv6 allocation
- [ ] **NAT Traversal** - Advanced traversal techniques leveraging QUIC's connection migration
- [ ] **Multi-Zone Resilience** - Zone-based fail-over and load balancing across multiple nodes
- [ ] **Persistence Layer** - Durable storage for DNS records with versioning and replication
- [ ] **Advanced Security Features** - DNSSEC integration, zero-knowledge proofs
- [ ] **Cross-Network Resolution** - Safe delegation between different network scopes with policy enforcement
- [ ] **Performance Optimization** - Caching strategies, connection pooling, and reduced latency mechanisms
- [ ] **API Stabilization** - Finalization of public APIs with backward compatibility guarantees
- [ ] **Protocol Formalization** - Complete specification documentation with RFC-style protocol definition
- [ ] **Extended CLI Capabilities** - Advanced network management and diagnostic tools
- [ ] **Scalability Testing** - Large-scale deployment testing with thousands of concurrent connections
- [ ] **Error Handling Improvements** - Comprehensive error recovery with graceful degradation
- [ ] **Logging & Diagnostics** - Enhanced logging system with structured output and severity levels
- [ ] **Documentation** - Comprehensive user, developer, and protocol documentation

### Current Implementation Notes
- CLI interface supports all required commands for testing and operation
- Stub implementations provide fallback functionality when service isn't running
- Integration tests pass with full implementations for core functionality
- IPv6 support is fully integrated and tested
- QUIC handshake is stable with improved error handling for certificate management
- Certificate creation and validation are fully implemented using Falcon post-quantum signatures
- Certificate Authority (CA) infrastructure now uses Falcon for all signature operations
- Certificate Transparency logs now support Falcon signatures for improved security
- CLI interface displays Falcon certificate validation status
- Falcon integration is verified through comprehensive component tests
- Multi-network support is operational but needs more thorough security boundary testing
- Configuration management is fully functional with profile support and auto-detection
- Network contexts maintain proper isolation between different network instances
- Current DNS resolution handles basic AAAA records via direct server query; resolver logic and support for other record types are pending
- Tunneling support is partially implemented but IPv6 allocation per tunnel needs completion
- Service architecture supports background operation with proper lifecycle management
- P2P connections work but need more extensive NAT traversal capability
- QUIC transport layer is integrated with ngtcp2 with compatibility fixes for different library versions
- Private/Public/Federated modes are all implemented and functioning with appropriate isolation
- Memory usage is stable with improved memory safety
- Error handling is implemented with improved robustness in critical paths

## Testing

### Prerequisites

Before beginning testing, ensure you have:

1. A system with IPv6 enabled
2. The NEXUS software built (`make all`)
3. Sufficient permissions to open network ports

### Testing Methods

NEXUS offers several testing methods, from unit tests to full integration testing:

#### 1. Unit Tests

Unit tests verify individual components:

```bash
# Run all unit tests
make test

# Run specific component tests
make test_tld        # TLD Manager
make test_packet     # Packet Protocol
make test_config     # Config Manager
make test_cli        # CLI Interface
make test_ct         # Certificate Transparency
make test_ca         # Certificate Authority
make test_network    # Network Context
```

#### 2. QUIC Handshake Tests

These tests verify the QUIC handshake process:

```bash
# Test basic QUIC handshake
make test_handshake

# Test IPv6 QUIC handshake and certificate verification
make test_ipv6
```

#### 3. Full Integration Testing

The integration test verifies all components working together:

```bash
make integration_test
```

This runs `tests/nexus_integration_test.sh`, which tests:
- Starting servers and clients across multiple networks (private, public, federated)
- IPv6 connectivity
- Certificate creation and validation
- TLD registration
- Domain registration
- DNS resolution
- Data transmission between nodes

Additionally, a dedicated Falcon post-quantum cryptography integration test is available:

```bash
./tests/integration_falcon_test.sh
```

This test specifically focuses on:
- Server and client initialization with Falcon certificates
- Verification of Falcon certificate validation during handshakes
- DNS resolution with Falcon certificate verification
- Data transfer with post-quantum security

### Manual Testing

For manual testing, follow these steps:

1. **Start a NEXUS server**:
   ```bash
   ./build/nexus --mode private --hostname server.nexus.local --bind-address ::1 --port 10443
   ```

2. **Start a NEXUS client**:
   ```bash
   ./build/nexus --mode private --hostname client.nexus.local --server ::1 --server-port 10443
   ```

3. **Register a TLD**:
   ```bash
   ./build/nexus_cli --server ::1 --port 10443 register-tld "test"
   ```

4. **Register a domain**:
   ```bash
   ./build/nexus_cli --server ::1 --port 10443 register-domain "example.test" "fd00::1"
   ```

5. **Resolve a domain**:
   ```bash
   ./build/nexus_cli --server ::1 --port 10443 resolve "example.test"
   ```

6. **Verify a certificate**:
   ```bash
   ./build/nexus_cli --server ::1 --port 10443 verify-cert "client.nexus.local"
   ```

7. **Send data**:
   ```bash
   ./build/nexus_cli --server ::1 --port 10443 send-data "server.nexus.local" "Hello NEXUS!"
   ```

### Verifying IPv6 Functionality

NEXUS is designed to work natively with IPv6, providing:
- Full IPv6 support for all connections
- IPv6 address allocation for tunnels
- IPv6-based certificate binding
- IPv6 DNS record storage and resolution

To verify IPv6 functionality:

1. **Check that connections are established over IPv6**:
   ```bash
   ss -tulpn | grep nexus
   ```
   Look for entries with IPv6 addresses (starting with `::`)

2. **Verify DNS resolution returns IPv6 addresses**:
   ```bash
   ./build/nexus_cli --server ::1 --port 10443 resolve "example.test"
   ```
   The result should be an IPv6 address.

3. **Confirm certificates are created for IPv6 connections**:
   ```bash
   ./build/nexus_cli --server ::1 --port 10443 cert-info "client.nexus.local"
   ```
   The certificate should include IPv6 address information.

4. **Test IPv6 QUIC handshake**:
   ```bash
   make test_ipv6
   ```

### Test Implementation

The tests are structured to validate both API functionality and integration between components:

1. **Unit Tests** - Verify individual functions and modules in isolation
2. **Integration Tests** - Test the interaction between multiple components
3. **Mock Components** - Provide controlled test environments
4. **Assertion-Based Testing** - Clear validation of expected behaviors

Each test file follows a consistent pattern with setup, test execution, and cleanup phases to ensure reliable and repeatable testing.

### Troubleshooting

#### Connection Issues

If connections fail:

1. **Verify IPv6 is enabled on your system**:
   ```bash
   ping6 -c 3 ::1
   ```

2. **Check if ports are already in use**:
   ```bash
   ss -tulpn | grep 10443
   ```

3. **Enable debug output**:
   ```bash
   NEXUS_DEBUG=1 ./build/nexus --mode private --hostname test.local
   ```

4. **Examine logs for specific errors**:
   ```bash
   # In integration test mode
   cat logs/server_private_10443.log
   cat logs/client_private_client1.local.log
   ```

#### Certificate Issues

If certificate verification fails:

1. **Check that the CA is properly initialized**:
   ```bash
   ./build/nexus_cli --server ::1 --port 10443 ca-status
   ```

2. **Verify the certificate was created**:
   ```bash
   ./build/nexus_cli --server ::1 --port 10443 list-certs
   ```

#### DNS Resolution Issues

If DNS resolution fails:

1. **Verify the TLD is registered**:
   ```bash
   ./build/nexus_cli --server ::1 --port 10443 list-tlds
   ```

2. **Check that the domain is registered**:
   ```bash
   ./build/nexus_cli --server ::1 --port 10443 list-domains "test"
   ```

### Advanced Testing

After verifying basic functionality, consider testing:

1. **Load Testing**: Multiple simultaneous connections
2. **Failover**: Server/client recovery after connection loss
3. **Cross-Network**: Communication between different network types
4. **Certificate Transparency**: Verify CT logs across network boundaries

## Falcon Post-Quantum Cryptography

NEXUS now integrates the Falcon post-quantum signature algorithm for certificate operations, providing quantum-resistant security throughout the system.

### Features

- **Post-Quantum Secure Certificates**: All certificates are generated and verified using Falcon signatures
- **CA Infrastructure**: Certificate Authority operations use Falcon for key generation and certificate signing
- **Certificate Transparency**: CT logs use Falcon signatures for tamper-proof verification
- **Certificate Verification**: Certificate validation during QUIC handshakes uses Falcon verification

### Testing Falcon Integration

You can verify the Falcon integration with the following tests:

```bash
# Run standalone CA tests to verify Falcon key generation and certificate operations
make test_ca

# Run standalone CT tests to verify Falcon signature handling in certificate transparency
make test_ct

# Run the dedicated Falcon integration test
./tests/integration_falcon_test.sh
```

The integration test verifies:
- Falcon certificate generation during server/client initialization
- Falcon certificate validation during connection handshakes
- DNS resolution with Falcon-verified certificates
- Data transfer with Falcon certificate validation

### CLI Commands for Falcon Verification

The CLI interface has been updated to display Falcon certificate validation status:

```bash
# Check certificate status (will show Falcon validation)
./build/nexus_cli status

# Verify a specific certificate using Falcon
./build/nexus_cli verify-cert <hostname>
```

### Integration Points

Falcon has been integrated at several key points in the system:
- Key generation in the CA module
- Certificate signing operations
- Certificate verification during handshakes
- Certificate Transparency log signatures
- DNS-level certificate validation during resolution

## Building

```bash
make clean && make
```


#### Debug Mode

Run the daemon with verbose logging:
```bash
NEXUS_DEBUG=1 ./build/nexus --profile home
```

#### Verify Connections

```bash
# Check if service is running
./build/nexus_cli status

# Test DNS resolution
./build/nexus_cli lookup test.example
```

## Architecture Components
1. **NEXUS Client**: Sends/receives DNS requests over QUIC, operates in dual client/server mode to enable decentralized communications across multiple NEXUS servers.

2. **NEXUS Server**: Dedicated server that handles requests from multiple NEXUS clients.

3. **NEXUS Resolver**: Queries other resolvers within the hypermesh network to resolve DNS requests.

These components can run on the same machine or be distributed across different systems.

## Operation Modes
- **Private Mode**: Acts as both client and server on the same node. Enables registration of private domains for internal use within a private hypermesh network. Each node operates as its own host and mirror for redundancy.

- **Public Mode**: Connects to established NEXUS network (e.g., dns.hypermesh.online) to access globally registered domains. Acts primarily as a client to query TLDs from the network.

- **Federated Mode**: Operates as both client and server, but connects to other NEXUS nodes to form a federated network. Can register domains and serve as a mirror for other nodes.

### Multi-Network Support

NEXUS supports simultaneous operation across multiple networks with different scopes and security boundaries:

- **Network Isolation**: Run multiple network instances simultaneously with strict isolation between them
- **Independent Contexts**: Maintain separate configuration, credentials, and state for each network
- **Scope-Based Routing**: Route requests to the appropriate network based on domain scope and request type
- **Cross-Network Policy**: Define explicit policies for how/if information can flow between networks
- **Network Profiles**: Save and switch between different network configurations easily

Example Multi-Network Configuration:
- A private home network for personal devices with local-only TLDs
- A federated work network with access to company resources and controlled sharing
- A public hypermesh connection for accessing the broader community
- Ephemeral P2P connections for direct device-to-device communication without exposing other networks

Each network operates with its own independent:
- Certificate authorities and trust chains
- Peer lists and connection policies
- DNS records and resolution paths
- Resource access controls
- Performance and security settings

Networks can be activated, deactivated, or reconfigured independently without affecting other connections.

## Advanced Configuration

### Certificate Management

NEXUS uses Falcon quantum-resistant certificates for authentication. Custom certificates can be specified in profile configurations:

```bash
./build/nexus_cli edit-profile home ca_cert_path /path/to/ca.cert
./build/nexus_cli edit-profile home cert_path /path/to/node.cert
./build/nexus_cli edit-profile home private_key_path /path/to/private.key
```

### Network Tuning

Optimize network performance:

```bash
# Adjust connection parameters
./build/nexus_cli edit-profile home max_tunnels 20

# Enable NAT traversal for complex networks
./build/nexus_cli edit-profile home enable_nat_traversal true
```

### Multiple Instances

Run multiple NEXUS instances with different configurations:

```bash
# Start first instance on default ports
./build/nexus --profile home

# Start second instance with custom ports in a different terminal
./build/nexus --profile public --server-port 20053 --client-port 20443
```

## NEXUS and Hypermesh Integration

NEXUS is designed to function both as a standalone protocol and as the core networking layer for the Hypermesh framework (codename NKrypt). This dual-purpose architecture ensures maximum flexibility while providing seamless integration between networking and blockchain components.

### Modular Architecture

NEXUS follows a "Core-Extensions" architecture pattern:

- **Core Components**: Standalone functionality that operates independently
  - QUIC Transport Layer
  - DNS Resolution System
  - Certificate Management
  - Connection Handling
  - TLD/Domain Management

- **Extension Interfaces**: Well-defined integration points for Hypermesh
  - Asset Resolution Bridge
  - Blockchain Connector
  - Token Authentication
  - Advanced Distributed Features

This separation allows NEXUS to operate in both standalone mode and as an integrated component of the larger Hypermesh ecosystem.

### Interface Architecture

NEXUS provides a standardized interface layer for Hypermesh integration:

1. **Dynamic Component Registry**
   - Runtime registration of both core and extension components
   - Capability discovery and feature negotiation
   - Graceful degradation when Hypermesh components aren't available
   - Plugin architecture for extended functionality

2. **Asset Resolution Interface**
   - Extensions to DNS resolution for blockchain assets
   - Mapping between traditional domains and asset identifiers
   - Caching optimized for both DNS and asset resolution
   - Unified query interface spanning both systems

3. **Token Verification**
   - Support for token-based authentication across network boundaries
   - Verification of token validity against blockchain state
   - Caching of token verification results for performance
   - Rate limiting and protection against token-based attacks

### Integration Patterns

When operating as part of the Hypermesh ecosystem, NEXUS:

1. **Delegates Asset Management** to NKrypt:
   - Asset creation, validation, and state management remain in NKrypt
   - NEXUS focuses on asset discovery, resolution, and network communication
   - Clear separation of concerns between network and blockchain layers

2. **Provides Communication Infrastructure** for NKrypt:
   - Secure QUIC-based transport for all Hypermesh communications
   - Multi-path routing for resilient blockchain operations
   - Efficient block and transaction propagation
   - Connection management optimized for blockchain workloads

3. **Enables Cross-Network Operations**:
   - Discovery of assets across network boundaries
   - Secure communication between different Hypermesh instances
   - Token-based authentication for cross-network operations
   - Bandwidth and resource management for network-spanning requests

### Configuration and Deployment

NEXUS can be configured for different operational modes:

```json
{
  "mode": "standalone",  // or "integrated"
  "hypermesh_interface": {
    "enabled": true,
    "registry_endpoint": "http://localhost:8545",
    "token_verification": true,
    "asset_resolution": true
  }
}
```

This configuration-driven approach allows for flexible deployment scenarios:

- **Standalone Mode**: NEXUS operates as an independent DNS-over-QUIC service
- **Integrated Mode**: NEXUS works in concert with Hypermesh components
- **Hybrid Mode**: NEXUS provides both standalone services and Hypermesh integration

### Development and Extension

Developers can extend NEXUS's capabilities through:

1. **Interface Implementation**: Creating new implementations of standard interfaces
2. **Component Registration**: Registering components with the dynamic registry
3. **Protocol Extensions**: Developing new message types and handlers
4. **Custom Resolvers**: Implementing specialized resolution for different asset types

The plugin architecture ensures that NEXUS can evolve alongside the Hypermesh ecosystem while maintaining its core functionality as a standalone protocol.

## Testing

### Unit Tests

Run the unit tests to verify individual components:

```bash
make test
```

### Full Stack Testing

Run the full stack test to verify all components working together:

```bash
./run_full_stack_test.sh
```

This script tests:
1. Building the project
2. Running unit tests
3. Testing Falcon cryptography integration
4. Testing TLD registration
5. Testing domain registration and DNS lookups
6. Testing federation between servers

### Falcon Integration Tests

Run the Falcon cryptography integration tests:

```bash
./test_falcon.sh
```

This verifies the Falcon post-quantum cryptography implementation.
