import scapy.all as scapy


def sniff_packets(interfaces, count):
    captured_data = {}
    print(f"Sniffing {count} packets on each of the following interfaces: {', '.join(interfaces)}...")
    for interface in interfaces:
        try:
            print(f"\nSniffing on interface: {interface}")
            packets = scapy.sniff(iface=interface, count=count, timeout=10)  # timeout ensures it stops after a while
            captured_data[interface] = packets
        except Exception as e:
            print(f"Error capturing packets on {interface}: {e}")
    return captured_data


def analyze_packets(captured_data):
    print("\nAnalyzing captured packets...")
    for interface, packets in captured_data.items():
        print(f"\nInterface: {interface} - {len(packets)} packets captured")
        for packet in packets:
            print(packet.summary())
        print("-" * 50)


def main():
    """Main function to list interfaces, sniff packets, and analyze them."""
    # List available interfaces
    print("Available interfaces:")
    interfaces = scapy.get_if_list()
    for iface in interfaces:
        print(f" - {iface}")

    # Ask for the number of packets to sniff
    try:
        count = int(input("\nEnter the number of packets to sniff per interface: "))
        if count <= 0:
            print("Packet count must be a positive integer.")
            return
    except ValueError:
        print("Invalid input. Please enter a number.")
        return

    # Sniff packets on all available interfaces
    captured_data = sniff_packets(interfaces, count)

    # Analyze captured packets
    analyze_packets(captured_data)


if __name__ == "__main__":
    main()
