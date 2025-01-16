# Network Scanner

**PYNetwork** scanner is a tool using which you can scan the devices in your local network, then you can do port scanning, OS detection, and MAC vendor lookup.


<p align="center">
  <img src="https://img.icons8.com/?size=300&id=9b5wowKIlo9d&format=png&color=000000" alt="Scanner"/>
</p>
## Features

- Scan the active devices in your local network
- Choose the target and do port scanning on the remote server
- OS detection using TTL
- MAC vendor lookup

## Installation

To use PYNetworkScanner, you need to have Python installed on your system. You can clone the repository and run the script directly.

```bash
git clone https://github.com//link
cd project/
```

## Usage

You can run this script with various command line arguments to perform different actions.

```
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

Happy Hacking!

```

## Note
You must run this script as root or use sudo to run this script for it to work properly. This is because changing a MAC address requires root privileges.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgements

Developed by AGT Cyber.

