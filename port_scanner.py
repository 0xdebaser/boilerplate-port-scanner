import socket
import re
from common_ports import ports_and_services
import nmap


def get_open_ports(target, port_range, verbose=False):
    scanner = nmap.PortScanner();
    open_ports = []

    is_URL = re.search('[a-zA-Z]', target)
    if is_URL is None:
        try:
            socket.inet_aton(target)
            ip_address = target
        except socket.error:
            return "Error: Invalid IP address"
    else:
        try:
            ip_address = socket.gethostbyname(target)
        except socket.gaierror:
            return "Error: Invalid hostname"
    
    print(f"Scanning: {ip_address}")    
    scanner.scan(ip_address, f"{port_range[0]}-{port_range[1]}")
    ports = list(scanner[ip_address]["tcp"].keys())
    for port in ports:
        if scanner[ip_address]["tcp"][port]["state"] == "open":
            open_ports.append(port)
 
    if verbose:
        if scanner[ip_address].hostname():        
            report = f"Open ports for {scanner[ip_address].hostname()} ({ip_address})\n"
        else:
            report = f"Open ports for {ip_address}\n"
        report += "PORT     SERVICE"
        for port in open_ports:
            report += f"\n{str(port).ljust(4)}     {ports_and_services[port]}"
        return report
    else:
        return(open_ports)