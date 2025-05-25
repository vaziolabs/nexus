# NEXUS Network Suite

## Overview
NEXUS is a simple, secure, scalable DNS-over-QUIC protocol implementation designed for the hypermesh network, providing enhanced security, performance, and scalability features for distributed DNS. Beyond DNS, NEXUS is designed to evolve into a comprehensive network protocol replacement leveraging QUIC's capabilities to handle tunneling, IPv6 allocation, and NAT traversal.

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

## Implementation Status

### Completed Components
- [x] **Configuration Management System** - Auto-detection of network settings and profile management
- [x] **Multi-Network Architecture** - Support for running multiple isolated networks simultaneously
- [x] **CLI Interface** - Command-line tools for managing the NEXUS service and network profiles
- [x] **Certificate Transparency** - Federated scope-based CT logs with Merkle tree verification
- [x] **Service Architecture** - Daemon mode with proper service lifecycle management
- [x] **Basic Core DNS Functionality** - DNS request/response handling and TLD management
- [x] **QUIC Transport Integration** - Utilizes ngtcp2 for secure and reliable transport

### In Progress Components
- [ ] **Advanced DNS Resolution** - Complete implementation of recursive and iterative resolution
- [ ] **TLD Mirroring** - Robust synchronization with automatic conflict resolution
- [ ] **Enhanced Certificate Management** - Comprehensive validation and quantum-resistant algorithms
- [ ] **Peer Discovery** - Automatic network topology mapping
- [ ] **Metrics Collection** - Performance monitoring and optimization
- [ ] **Tunneling Infrastructure** - Implementation of per-tunnel IPv6 allocation
- [ ] **NAT Traversal** - Advanced traversal techniques leveraging QUIC's connection migration

### Testing Infrastructure
We have implemented a comprehensive testing framework covering the following components:
- [x] **TLD Manager Tests** - Verify domain registration and resolution
- [x] **Packet Protocol Tests** - Validate packet encoding/decoding and handling
- [x] **Configuration Manager Tests** - Test profile creation, management, and loading
- [x] **CLI Interface Tests** - Verify command parsing and execution
- [x] **Certificate Transparency Tests** - Test CT log operations and Merkle tree verification
- [x] **Certificate Authority Tests** - Validate certificate issuance, verification, and management
- [x] **Network Context Tests** - Verify proper handling of different network modes and contexts
- [x] **QUIC Handshake Tests** - Validate secure connection establishment

## Practical Use Cases
1. **Central DNS Gateway**: Run a dedicated NEXUS node at dns.hypermesh.online to serve as the primary entry point to the hypermesh DNS ecosystem.

2. **Private Domain Registration**: Run NEXUS locally in private mode to register and use custom TLDs without depending on central authorities.

3. **Distributed DNS Network**: Connect multiple NEXUS nodes in federated mode to create a resilient, distributed DNS network with shared TLD management.

4. **Client Access**: Use NEXUS in public mode to connect to the hypermesh network and resolve domains registered by other participants.

## Security Model
- All nodes require valid Falcon quantum-resistant certificates for authentication
- Client and server certificates are validated for all communications
- Certificate authority management ensures proper issuance and validation
- Certificate Transparency logs provide auditable certificate issuance history
- Private keys are never shared between networks to maintain isolation

## Core Features

### P2P Network Management
- Peer discovery and connection handling
- State tracking for each peer
- Thread-safe peer list management

### DNS Consensus System
- 100% consensus requirement for DNS records
- Signature collection from all active peers
- Timeout handling for consensus requests
- Thread-safe consensus operations

### Security Features
- Falcon-1024 signatures for DNS records
- Multiple signature verification
- Timestamp and TTL validation
- Peer validation

The consensus mechanism ensures:
- All active peers must validate and sign new DNS records
- Any single peer can veto a malicious DNS record
- Records are timestamped and signed to prevent replay attacks

## NEXUS as a Network Protocol Replacement

NEXUS is designed to evolve beyond DNS services to function as a comprehensive network protocol replacement for the hypermesh network. This section outlines how NEXUS will handle core networking functions:

### Tunneling Capabilities
- Each connection via the hypermesh network operates as its own isolated tunnel
- Per-tunnel encryption using QUIC's TLS 1.3 security model
- Support for multiple simultaneous tunnels with independent routing
- Tunnel persistence across network changes (leveraging QUIC migration)
- Tunnel-specific QoS (Quality of Service) controls
- Built-in congestion control per tunnel

### IPv6 Allocation and Management
- Dynamic IPv6 address allocation per tunnel
- IPv6 prefix delegation for subnet management
- Address collision detection and resolution
- Address rotation for enhanced privacy
- Support for both temporary and persistent addressing schemes
- Integration with existing IPv6 infrastructure

### NAT Traversal and Translation
- Advanced NAT traversal techniques leveraging QUIC's connection migration
- Automatic NAT type detection and optimization
- Direct peer-to-peer connections where possible
- Relay capabilities for symmetric NAT scenarios
- Transparent address translation between public and private networks
- Support for both IPv4-to-IPv6 and IPv6-to-IPv4 translation

### Mesh Networking Capabilities
- Dynamic route discovery and optimization
- Multi-path routing for redundancy and performance
- Resilient connections across changing network conditions
- Peer-assisted routing to optimize paths through the network
- Automatic fail-over and load balancing
- Support for network partitioning and rejoining

This expanded role positions NEXUS as the foundation for the entire hypermesh network infrastructure, not just DNS services. The protocol will maintain backward compatibility with standard Internet protocols while providing enhanced capabilities for hypermesh-aware applications.

## Next Steps/TODO
  - [ ] Complete DNS resolution functionality with full recursive and iterative resolution support
  - [ ] Implement robust TLD mirroring for federated networks with automatic sync and conflict resolution
  - [ ] Enhance certificate management with more comprehensive validation and revocation checking
  - [ ] Add support for certificate rotation and quantum-resistant algorithms
  - [ ] Implement full packet types defined in network_context.h (especially sync, discovery, and heartbeat)
  - [ ] Add support for peer discovery and automatic network topology mapping
  - [ ] Create a metrics collection system for performance monitoring and optimization
  - [ ] Develop administrative interfaces for network management and monitoring
- [ ] Develop remaining test suites for certificate authority, nexus_client, nexus_server, and network_context
- [ ] Implement per-tunnel IPv6 allocation system
- [ ] Add NAT traversal and translation capabilities
- [ ] Develop tunnel management interface for applications
- [ ] Create APIs for applications to access tunneling capabilities
- [ ] Implement multi-path routing with redundancy
- [ ] Add automatic fail-over and load balancing

## Testing
The NEXUS project includes a comprehensive testing framework covering all major components. Tests are implemented as individual test files for each component, with a main test runner that executes all tests.

To run the complete test suite:
```bash
make test
```

This will execute tests for all major components:
- **TLD Manager Tests** - Verify domain registration and resolution
- **Packet Protocol Tests** - Validate packet encoding/decoding for various message types
- **Configuration Manager Tests** - Test profile creation, management, and loading
- **CLI Interface Tests** - Verify command parsing and execution
- **Certificate Transparency Tests** - Test CT log operations and Merkle tree verification
- **Certificate Authority Tests** - Validate certificate issuance, verification, and management
- **Network Context Tests** - Verify proper handling of different network modes and contexts
- **QUIC Handshake Tests** - Validate secure connection establishment

### Individual Test Components

You can run specific test components separately:

```bash
# Run only the QUIC handshake test
make test_handshake

# Run only the TLD manager tests
make test_tld
```

### Test Implementation

The tests are structured to validate both API functionality and integration between components:

1. **Unit Tests** - Verify individual functions and modules in isolation
2. **Integration Tests** - Test the interaction between multiple components
3. **Mock Components** - Provide controlled test environments
4. **Assertion-Based Testing** - Clear validation of expected behaviors

Each test file follows a consistent pattern with setup, test execution, and cleanup phases to ensure reliable and repeatable testing.

## Building

```bash
make clean && make
```

## Running

NEXUS provides two executables:

### NEXUS Daemon
```bash
./build/nexus --help
```

Example of running the daemon:
```bash
./build/nexus --mode private --hostname localhost --server localhost
```

### NEXUS CLI
```bash
./build/nexus_cli help
```

Example CLI commands:
```bash
# Show status of the NEXUS service
./build/nexus_cli status

# Register a TLD in a specific profile
./build/nexus_cli register-tld myprofile example

# List available profiles
./build/nexus_cli list-profiles
```

## License
See LICENSE file.