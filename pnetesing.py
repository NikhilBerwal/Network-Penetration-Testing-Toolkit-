import socket
from scapy.all import ARP, Ether, srp
import itertools


# port scanner

def port_scanner(target_ip, ports):
    print(f"Scanning {target_ip} for open ports...")
    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                result = s.connect_ex((target_ip, port))
                if result == 0:
                    open_ports.append(port)
        except Exception as e:
            print(f"Error scanning port {port}: {e}")
    if open_ports:
        print(f"Open ports on {target_ip}: {open_ports}")
    else:
        print(f"No open ports found on {target_ip}")

# network mapper

def network_mapper(target_ip_range):
    print(f"Mapping network: {target_ip_range}")
    arp_request = ARP(pdst=target_ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp_request
    result = srp(packet, timeout=3, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({'IP': received.psrc, 'MAC': received.hwsrc})

    if devices:
        print("Devices found in network:")
        for device in devices:
            print(f"IP: {device['IP']}, MAC: {device['MAC']}")
    else:
        print("No devices found in the network.")

#simple bruteforce password guesser

def password_guesser(target_ip, port, username, password_list):
    print(f"Attempting brute-force on {target_ip}:{port} with username: {username}")
    for password in password_list:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                result = s.connect_ex((target_ip, port))
                if result == 0:
                    # Example placeholder for sending username and password to the target service
                    # The real implementation depends on the protocol of the target service (e.g., FTP, SSH)
                    s.sendall(f"{username}:{password}\n".encode())
                    response = s.recv(1024).decode()
                    if "success" in response:  # Placeholder condition
                        print(f"Password found: {password}")
                        return password
        except Exception as e:
            print(f"Error during brute-force attempt: {e}")
    print("Password not found in the provided list.")
    return None
... 

... # Main Function

""" ... if __name__ == "__main__":
...     # Example Usage
...     target_ip = "192.168.1.1"
...     ports_to_scan = [21, 22, 80, 443, 8080]  # Modify as needed
... 
...     # Run Port Scanner
...     port_scanner(target_ip, ports_to_scan)
... 
...     # Run Network Mapper
...     target_ip_range = "192.168.1.0/24"
...     network_mapper(target_ip_range)
... 
...     # Run Password Guesser
...     username = "admin"
...     password_list = ["123456", "password", "admin123", "root"]  # Modify as needed
...     port_to_test = 22  # Example: SSH port """

# Main Function

if __name__=="__main__":
    #example
    target_ip = "192.168.1.1"
    ports_to_scan = [21, 22, 80, 443, 8080]  # Modify as needed

    # Run Port Scanner
    port_scanner(target_ip, ports_to_scan)

    # Run Network Mapper
    target_ip_range = "192.168.1.0/24"
    network_mapper(target_ip_range)

    # Run Password Guesser
    username = "admin"
    password_list = ["123456", "password", "admin123", "root"]  # Modify as needed
    port_to_test = 22  # Example: SSH port
    password_guesser(target_ip, port_to_test, username, password_list)

