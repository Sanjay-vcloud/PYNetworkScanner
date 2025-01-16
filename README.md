# Network Scanner

**PYNetworkScanner** is a powerful tool that allows you to scan devices in your local network, perform port scanning, detect operating systems, and look up MAC vendors.

<p align="center">
  <img src="https://img.icons8.com/?size=300&id=9b5wowKIlo9d&format=png&color=000000" alt="Scanner"/>
</p>

## Features

- **Network Scanning**: Discover active devices in your local network.
- **Port Scanning**: Scan for open ports on a target device.
- **OS Detection**: Identify the operating system of a target device using TTL values.
- **MAC Vendor Lookup**: Find the vendor of a device using its MAC address.

## Installation

To use PYNetworkScanner, you need to have Python installed on your system. You can clone the repository and run the script directly.

```bash
git clone https://github.com/Sanjay-vcloud/PYNetworkScanner.git
cd NetworkScanner
```

## Usage

You can run this script with various command-line arguments to perform different actions.

```bash
    _   _  _____ _____   _____ _____   ___   _   _  _   _  ___________ 
    | \ | ||  ___|_   _| /  ___/  __ \ / _ \ | \ | || \ | ||  ___| ___ \
    |  \| || |__   | |   \ `--.| /  \// /_\ \|  \| ||  \| || |__ | |_/ /
    | . ` ||  __|  | |    `--. \ |    |  _  || . ` || . ` ||  __||    / 
    | |\  || |___  | |   /\__/ / \__/\| | | || |\  || |\  || |___| |\ \ 
    \_| \_/\____/  \_/   \____/ \____/\_| |_/\_| \_/\_| \_/\____/\_| \_|
                                                                    
                                                                    
    
usage: NetworkScanner [-h] [-t TARGET] [-s SCAN] [-p PORTS] [-o] [-l] [-V VENDOR] [-v]

Network Scanner Tool

options:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        Target IP address
  -s SCAN, --scan SCAN  Scan for devices in the network (e.g., 192.168.1.0/24)
  -p PORTS, --ports PORTS
                        Port range to scan (e.g., 1-100)
  -o, --os              Detect OS using scanning techniques
  -l, --local           Get Local IP Address
  -V VENDOR, --vendor VENDOR
                        Get vendor by MAC address
  -v, --version         show program's version number and exit

### Examples

#### Scan for Devices in the Network

```bash
python3 main.py -s 192.168.1.0/24
```

#### Port Scanning

```bash
python3 main.py -t 192.168.1.1 -p 1-100
```

#### OS Detection

```bash
python3 main.py -t 192.168.1.1 -o
```

#### MAC Vendor Lookup

```bash
python3 main.py -V 00:11:22:33:44:55
```

#### Get Local IP Address

```bash
python3 main.py -l
```

## Note
You must run this script as root or use sudo to run this script for it to work properly. This is because some operations require root privileges.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgements

Developed by AGT Cyber.

