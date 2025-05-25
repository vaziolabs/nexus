from network_node import NetworkNode
from concensus_network import ConsensusNetwork
from decentralized_dns import DecentralizedDNS

def main():
    # Create a consensus network requiring at least 2 consensus nodes
    network = ConsensusNetwork(min_consensus_nodes=2)

    # Create some network nodes (including consensus authorities)
    authority1 = NetworkNode("auth1", is_consensus_authority=True)
    authority2 = NetworkNode("auth2", is_consensus_authority=True)
    regular_node = NetworkNode("node1", is_consensus_authority=False)

    # Add nodes to the network
    network.add_node(authority1)
    network.add_node(authority2)
    network.add_node(regular_node)

    # Create a decentralized DNS instance
    ddns = DecentralizedDNS(network)

    # Example: Add a DNS record
    try:
        print("Adding DNS record for example.com...")
        ddns.add_record(
            domain="example.com",
            record_type="A",
            value="192.168.1.1",
            requesting_node=regular_node
        )
        
        # Resolve the domain
        print("\nResolving example.com...")
        result = ddns.resolve("example.com")
        if result:
            print(f"Domain: example.com")
            print(f"Record Type: {result['type']}")
            print(f"Value: {result['value']}")
            print(f"Certificate: {result['certificate']}")
        else:
            print("Domain not found")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
