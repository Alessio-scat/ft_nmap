
# ft_nmap

## Project Overview
The **ft_nmap** project involves recreating parts of the Nmap port scanner, a popular network scanning tool used to detect open ports, identify services, and gather information about the operating systems of remote hosts. This project aims to provide an in-depth understanding of network security and the functionality of port scanning.

## Objectives
- Develop a custom port scanner that replicates key functionalities of Nmap.
- Implement various scan types such as SYN, NULL, ACK, FIN, XMAS, and UDP scans.
- Utilize threading to enhance scan speed and efficiency.
- Handle IPv4 addresses and hostnames, with support for reading targets from a file.
- Manage ports individually or in specified ranges, with a maximum of 1024 ports scanned.
- Display scan results clearly and concisely, with detailed information about open, filtered, or closed ports.

## Technologies Used
- **C Programming Language**: Core language used for development.
- **PCAP Library**: Used for packet capture and analysis.
- **Pthread Library**: Provides multithreading support to enhance scan performance.

## Key Features
- Supports multiple scan types: SYN, NULL, ACK, FIN, XMAS, and UDP.
- Ability to specify the number of threads for faster scanning (up to 250).
- Handles both individual ports and ranges, with a default range of 1-1024 if not specified.
- Displays comprehensive scan results, including service types and status of each port.

## How to Use
```
ft_nmap [--help] [--ports [NUMBER/RANGED]] --ip IP_ADDRESS [--speedup [NUMBER]] [--scan [TYPE]]
or
ft_nmap [--help] [--ports [NUMBER/RANGED]] --file FILE [--speedup [NUMBER]] [--scan [TYPE]]
```

### Example Commands
- Scan a specific IP with SYN scan and 70 threads:
  ```
  ./ft_nmap --ip 192.168.1.1 --speedup 70 --port 70-90 --scan SYN
  ```
- Scan from a file with multiple IP addresses using all scan types:
  ```
  ./ft_nmap --file targets.txt --speedup 150 --scan SYN,ACK,FIN
  ```

## License
This project is developed for educational purposes only. Unauthorized use of the code for malicious purposes is strictly prohibited.

## Credits
Project developed by Alessio as part of the 42 Cybersecurity curriculum.

