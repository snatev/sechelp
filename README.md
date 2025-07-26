<div align="center">

# Useful Security Services and Tools
A comprehensive collection of security services, tools, and information catering to a wide variety of uses.

![shield](https://github.com/snatev/sechelp/assets/169693246/502ffbdb-70d1-4c36-88b1-e690ab09546e)

<br>

### Navigation
[API Testing and Security](#api-testing-and-security)

[Metadata and File Analysis](#metadata-and-file-analysis)

[Log Analysis and Monitoring](#log-analysis-and-monitoring)

[Security Standards and Frameworks](#security-standards-and-frameworks)

[Network Analysis and Packet Capture](#network-analysis-and-packet-capture)

[Information Gathering and Enumeration](#information-gathering-and-enumeration)

[Web Application Enumeration and Fuzzing](#web-application-enumeration-and-fuzzing)

[Security Assessments and Threat Intelligence](#security-assessments-and-threat-intelligence)

<br><br>

</div>

### API Testing and Security

|||
|----------|-------------|
| **Postman** | Comprehensive API development environment that allows users to create, test, and document APIs, with features for automated testing and collaboration. |
| **Burp Suite** | Integrated platform for performing security testing of web applications, including tools for scanning, crawling, and advanced vulnerability detection. |
| **RequestBin** | Enables users to create custom endpoints to collect, inspect, and debug HTTP requests, facilitating API testing and webhook inspection. |

<br>

### Metadata and File Analysis

|||
|----------|-------------|
| **pdfinfo** | Command-line tool displaying PDF file information, such as title, author, subject, keywords, and page count, along with more details. |
| **ExifTool** | Platform-independent tool for reading, writing, and editing metadata in various file formats, offering comprehensive functionality. |
| **CyberChef** | Web-based tool for carrying out various encryption, encoding, compression, and data analysis operations, providing a simple and intuitive interface for complex tasks. |
| **Steghide** | Command-line steganography tool for embedding and extracting hidden data within various file formats like images and audio, while preserving file integrity. |
| **Binwalk** | Tool for analyzing binary files, commonly used to identify and extract embedded files or data. |
| **FLOSS** | Stands for FireEye Labs Obfuscated String Solver, a tool to automatically extract obfuscated and deobfuscated strings from malware binaries. |
| **jq** | Lightweight and flexible command-line JSON processor for parsing, manipulating, and formatting JSON data. |

<br>

### Log Analysis and Monitoring

|||
|----------|-------------|
| **ELK Stack** | Open-source stack combining Elasticsearch, Logstash, and Kibana to collect, search, analyze, and visualize log and monitoring data, widely used for security information and event management (SIEM). |
| **CloudWatch** | AWS monitoring and observability service for collecting and analyzing logs, metrics, and events to monitor infrastructure and applications in real-time. |
| **CloudTrail** | AWS service that provides governance, compliance, and operational auditing by logging API calls and activity across AWS accounts. |

<br>

### Security Standards and Frameworks

|||
|----------|-------------|
| **OSSTMM** | The Open Source Security Testing Methodology Manual, providing a peer-reviewed methodology for performing security tests and metrics. |
| **OWASP** | The Open Web Application Security Project, offering free and open resources focused on improving the security of software, including tools, documentation, and community support. |
| **NIST** | The National Institute of Standards and Technology, providing standards and guidelines to improve the security and resilience of information systems. |
| **NCSC CAF** | The National Cyber Security Centre Cyber Assessment Framework, offering guidance on how to assess and improve cyber security measures. |
| **OSINT** | Open-source intelligence tools and techniques for gathering and analyzing publicly available information to support security assessments and investigations. |
| **MITRE ATT&CK Framework** | A knowledge base of adversary tactics and techniques based on real-world observations, used for understanding and enhancing detection, response, and mitigation strategies. |

<br>

<br>

### Network Analysis and Packet Capture

|||
|----------|-------------|
| **tcpdump** | Command-line packet analyzer for capturing and inspecting network traffic in real time, supporting filtering and detailed output for in-depth network troubleshooting and analysis. |
| **Wireshark** | Comprehensive network protocol analyzer with a graphical interface for capturing and examining network packets in real-time or offline, supporting a wide range of protocols and use cases. |
| **TShark** | Command-line version of Wireshark for capturing and analyzing network traffic, ideal for scripting and headless environments. |
| **Ettercap** | Comprehensive suite for man-in-the-middle attacks on LAN, supporting sniffing of live connections, content filtering, and network protocol analysis. |
| **Bettercap** | Advanced, modular network attack and monitoring tool with support for network packet capture, man-in-the-middle attacks, and protocol manipulation. |

### Information Gathering and Enumeration

|||
|----------|-------------|
| **Nmap** | Network scanning tool for discovering devices, hosts, services, and vulnerabilities on a network. |
| **Wappalyzer** | Technology profiler that detects CMS, eCommerce platforms, web servers, JavaScript frameworks, and analytics tools on websites. |
| **OWASP Favicon Database** | Identifies web technologies based on favicon hashes, useful for gathering information about web applications. |
| **Wayback Machine** | Digital archive of the Web, enabling users to view historical versions of web pages for research and content recovery. |
| **crt.sh** | Queries Certificate Transparency logs to search for certificates issued for a domain, aiding in subdomain identification and security assessment. |
| **Netcat** | Versatile networking tool for reading from and writing to network connections using TCP or UDP, often used for network debugging and security testing. |
| **Socat** | Versatile networking tool for data transfer, port forwarding, and tunneling between two endpoints. Basically a more powerful version of Netcat. |
| **rlwrap** | Adds readline editing and history capabilities to command-line tools that lack them, enhancing usability during interactive sessions. |
| **Sublist3r** | Enumerates subdomains using multiple search engines and services like Netcraft, Virustotal, and DNSdumpster. |
| **Shodan** | Search engine for Internet-connected devices, allowing users to discover and analyze devices and services exposed to the Internet. |
| **dnsdumpster** | Online tool for performing DNS reconnaissance to discover hosts related to a domain. |
| **whois** | Queries domain registration records to retrieve details about ownership, registration dates, and contact information. |
| **nslookup** | Command-line tool for querying DNS to obtain domain name or IP address mapping, facilitating DNS troubleshooting and reconnaissance. |
| **dig** | Command-line DNS lookup utility providing detailed information about DNS queries, such as A, MX, and CNAME records. |
| **FoxyProxy** | Browser extension for managing multiple proxy configurations, streamlining proxy switching for security and anonymity purposes. |
| **User-Agent Switcher and Manager** | Browser extension allowing users to change their user-agent string for testing, anonymity, and bypassing restrictions. |
| **ping** | Network tool for testing reachability of hosts and measuring round-trip time for messages sent to a target. |
| **traceroute** | Network diagnostic tool that maps the path data takes to a host and identifies any intermediate hops. |
| **Masscan** | High-performance port scanner capable of scanning large sections quickly, used for identifying open ports and services. |

<br>

### Web Application Enumeration and Fuzzing

|||
|----------|-------------|
| **Gobuster** | Brute-forces URLs, DNS subdomains, and virtual host names in web applications, supporting directory/file brute-forcing and DNS enumeration. |
| **FFUF** | A fast web fuzzer for brute-forcing web applications, including directory/file discovery and virtual host name brute-forcing. |
| **Dirb** | Command-line tool for discovering hidden directories and files on web servers through brute-force attacks. |
| **WPScan** | WordPress security scanner that identifies vulnerabilities in WordPress installations, including plugins and themes. |
| **DNSRecon** | Performs DNS checks, including record enumeration, zone transfers, reverse lookups, and subdomain brute-forcing. |

<br>

### Security Assessments and Threat Intelligence

|||
|----------|-------------|
| **PayloadsAllTheThings** | Curated collection of offensive security payloads and techniques for web apps, APIs. |
| **SecLists** | Collection of lists used in security assessments, including usernames, passwords, URLs, sensitive data patterns, and fuzzing payloads. |
| **AbuseIPDB** | Collaborative project for reporting and checking IP addresses for malicious activities, helping to identify and mitigate threats. |
| **CrackStation** | Online password cracking tool using a massive database of known password hashes to recover passwords through hash comparison. |
| **HackerOne** | Platform connecting businesses with penetration testers and security researchers to identify and resolve security vulnerabilities through bug bounty programs. |
| **XSS Polyglots** | Collection of XSS payloads designed to test and bypass various XSS filters and protections, aiding in the detection and exploitation of XSS vulnerabilities. |
| **Command Injection Payload List** | Curated list of command injection payloads to test and exploit command injection vulnerabilities in web applications and services. |
| **Exploit-DB** | Archive of public exploits and corresponding vulnerable software, offering a comprehensive resource for security researchers and penetration testers. |
| **Atomic Red Team** | Open-source library of small, focused tests mapped to the MITRE ATT&CK framework to simulate adversary techniques and evaluate security controls. |
| **SearchSploit** | Command-line utility for offline searching of the Exploit-DB database, allowing quick access to public exploits and their references. |
| **John the Ripper** | Fast and customizable password cracker that supports a variety of hash types, widely used for security testing and forensic investigations. |
| **Hydra** | Fast and flexible brute-force password cracking tool supporting numerous protocols and services. |
| **msfvenom** | Payload generator that combines the functionality of msfpayload and msfencode, allowing users to create custom payloads for penetration testing and exploit development. |
| **Metasploit** | Powerful and flexible penetration testing framework with a vast library of exploits, payloads, and auxiliary modules to assess and validate vulnerabilities. |
