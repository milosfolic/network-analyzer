# Network Analyzer Tool

A simple network analyzer CLI tool written in Go for capturing and displaying network packets. The tool supports filtering by protocol, displaying DNS queries and HTTP requests, and updating the packet display in real-time.

## Features

- Capture packets from a specified network interface.
- Filter packets by protocol (TCP or UDP).
- Display DNS queries and responses.
- Display HTTP requests with method, URL, and host.
- Update the display table at a specified interval.
- Limit the number of rows shown in the table.

## Installation

1. Ensure you have Go installed on your system. If not, you can download and install it from [the Go website](https://golang.org/dl/).

2. Clone the repository:

    ```bash
    git clone https://github.com/milosfolic/network-analyzer.git
    ```

3. Change into the project directory:

    ```bash
    cd network-analyzer
    ```

4. Build the tool:

    ```bash
    go build -o netanalyzer
    ```

5. The `netanalyzer` binary will be created in the current directory.

## Usage

To run the tool, use the following command:

```bash
./netanalyzer [flags]
```

## Command-Line Flags

- -i, --interface (default: en0): Network interface to listen on.
- -p, --protocol (default: all): Protocol to filter (values: all, tcp, udp).
- -s, --save (default: ""): File to save captured packets in PCAP format.
- -d, --dns (default: false): Display DNS queries and responses.
- -t, --http (default: false): Display HTTP requests.
- -l, --limit (default: 20): Limit the number of rows displayed in the table.
- -u, --update-period (default: 5s): Time period for updating the table (e.g., 3s for 3 seconds).

## Examples

1. Capture packets on the default interface, showing DNS and HTTP information, with a row limit of 10 and an update interval of 3 seconds:

```bash
./netanalyzer -i en0 -d -t -l 10 -u 3s
```
2. Capture only TCP packets, save them to a file, and update the table every 10 seconds:

```bash
./netanalyzer -i eth0 -p tcp -s packets.pcap -u 10s
```
3. Capture packets without displaying DNS or HTTP information, and set a row limit of 50:

```bash
./netanalyzer -i wlan0 -l 50
```

## Notes
- Ensure you have appropriate permissions to capture packets on the specified network interface. You might need to run the tool with elevated privileges (e.g., using sudo on Unix-based systems).
- The tool relies on the gopacket library for packet capturing and analysis. If you encounter issues, ensure that all dependencies are properly installed.

## Contributing

Feel free to contribute to the project by submitting issues or pull requests. For major changes, please open an issue first to discuss what you would like to change.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.