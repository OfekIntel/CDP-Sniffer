# CDP Sniffer

A self-contained Cisco Discovery Protocol (CDP) packet analyzer written in C with statically linked libpcap.

## Overview

CDP Sniffer is a command-line tool designed to capture and decode Cisco Discovery Protocol (CDP) packets on a network. CDP is a proprietary protocol used by Cisco devices to share information with directly connected neighbors.

This tool allows network administrators to:
- Discover Cisco devices on a network
- View device identifiers, interfaces, and platform information
- Monitor CDP announcements in real-time

## Features

- **Self-Contained Binary**: The program includes a statically linked `libpcap` library, eliminating the need for external dependencies.
- **Real-time Packet Capture**: Captures and processes CDP packets as they are detected.
- **Protocol Decoding**: Extracts and displays key CDP fields, including:
    - Device ID
    - Port ID
    - Platform information
- **Filter Application**: Uses a BPF filter to capture only CDP packets based on the multicast MAC address `01:00:0c:cc:cc:cc`.

## Technical Details

- **Language**: C
- **Library**: Statically linked libpcap for packet capture
- **Protocol**: Decodes CDP packets using Type-Length-Value (TLV) fields
- **Filter**: Applies a Berkeley Packet Filter (BPF) for efficient packet selection

## Requirements

- Linux/Unix operating system
- Root/sudo permissions for packet capture

## Building

The project includes a statically linked `libpcap` library. To build the binary:

```bash
# Configure and build the statically linked libpcap
cd libpcap
./configure --disable-shared --disable-dbus --without-libnl
make -j$(nproc)

# Compile the CDP Sniffer with the static libpcap library
cd ..
gcc -static -o cdp_sniffer cdp_sniffer.c ./libpcap/libpcap.a -lm -lpthread -ldl
```

## Usage

```bash
# Run the program with sudo to allow packet capture
sudo ./cdp_sniffer
```

The program will automatically select the first available network interface and start capturing CDP packets. When a CDP packet is detected, it will display the extracted information.

## Disclaimer

This tool is intended for use by network administrators on networks they manage. Unauthorized use of packet capture tools may violate privacy laws and network policies.

## License

This project is licensed under the [MIT License](LICENSE).