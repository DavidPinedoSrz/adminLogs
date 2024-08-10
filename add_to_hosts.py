#!/usr/bin/env python3
import sys

if len(sys.argv) != 3:
    print("Uso: add_to_hosts.py <ip_address> <hostname>")
    sys.exit(1)

ip_address = sys.argv[1]
hostname = sys.argv[2]

try:
    with open('/etc/hosts', 'a') as hosts_file:
        hosts_file.write(f"{ip_address}\t{hostname}\n")
    print("Añadido con éxito.")
except Exception as e:
    print(f"Error: {e}")

