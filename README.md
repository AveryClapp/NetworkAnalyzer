# Network Protocol Analyzer

## Overview

This Network Protocol Analyzer is a high-performance C++ application designed to capture, parse, and analyze network traffic in real-time. It focuses on monitoring traffic to and from the device it's running on, providing valuable insights into network protocols, usage patterns, and potential security issues.

## Features

- **Real-time Packet Capture**: Efficiently captures network packets using the libpcap library.
- **Protocol Parsing**: Supports parsing of Ethernet, IP, TCP, and UDP protocols.
- **Multithreaded Architecture**: Utilizes multiple threads for improved performance and responsiveness.
- **Customizable Packet Filtering**: Allows users to set custom filters for targeted packet capture.
- **Detailed Packet Analysis**: Provides in-depth information about captured packets, including header details and payload.
- **User-friendly Logging**: Implements a flexible logging system for easy debugging and monitoring.

## Prerequisites

- C++17 compatible compiler (e.g., GCC 7+ or Clang 5+)
- CMake 3.10 or higher
- libpcap development libraries

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/network-protocol-analyzer.git
   cd network-protocol-analyzer
   ```

2. Create a build directory and run CMake:
   ```bash
   mkdir build && cd build
   cmake ..
   ```

3. Build the project:
   ```bash
   make
   ```

## Usage

1. Run the executable with root privileges (required for packet capture):
   ```bash
   sudo ./network_analyzer
   ```

2. Select a network interface when prompted.

3. Optionally, set a custom packet filter using Berkeley Packet Filter (BPF) syntax.

4. The analyzer will start capturing and analyzing packets. Press Ctrl+C to stop the capture.

## Configuration

- Logging level can be adjusted in the `logging.cpp` file.
- Default packet filters can be modified in the `PacketCaptureEngine.cpp` file.

## Project Structure

- `NetworkInterfaceManager`: Handles network interface selection and management.
- `PacketCaptureEngine`: Manages packet capture using libpcap.
- `ProtocolParser`: Parses captured packets and extracts protocol-specific information.
- `Logger`: Provides a flexible logging system for the application.
