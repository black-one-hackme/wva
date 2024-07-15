#!/usr/bin/env python3
import argparse
import random
import subprocess
import sys
import os
import time  # Ensure time module is imported

# ANSI color codes for colored output
RED = '\033[91m'
BLUE = '\033[94m'
GOLD = '\033[93m'
ENDC = '\033[0m'

# List of banners
banner_wva = [
    f"{GOLD} _       ___    _____ ",
    f"{GOLD}| |     / / |  / /   |",
    f"{GOLD}| | /| / /| | / / /| |",
    f"{GOLD}| |/ |/ / | |/ / ___ |",
    f"{GOLD}|__/|__/  |___/_/  |_|{ENDC}",
]

# List of available services and vulnerabilities
available_services = [
    "http", "https", "ssh", "ftp", "sftp", "smtp", "telnet", "dns", "mysql", "postgresql",
    "snmp", "udp", "icmp", "pop", "imap", "arp", "bgp", "ospf", "rip", "tcp"
]

# List of attack types
attack_types = [
    "Brute Force Attack", "Denial of Service (DoS) Attack", "Distributed Denial of Service (DDoS) Attack",
    "Man-in-the-Middle (MitM) Attack", "Phishing Attack", "Spear Phishing Attack", "Watering Hole Attack",
    "Smurf Attack", "SQL Injection Attack", "Cross-Site Scripting (XSS) Attack", "Cross-Site Request Forgery (CSRF) Attack",
    "Clickjacking Attack", "DNS Spoofing Attack", "Session Hijacking Attack", "Buffer Overflow Attack",
    "Eavesdropping Attack", "Insider Threat Attack", "Malware Attack", "Ransomware Attack", "Rootkit Attack",
    "Trojan Horse Attack", "Virus Attack", "Worm Attack", "Logic Bomb Attack", "Directory Traversal Attack",
    "Zero-Day Attack", "Credential Stuffing Attack", "Pharming Attack", "Replay Attack", "Side-Channel Attack",
    "Typosquatting Attack", "Drive-by Download Attack", "Social Engineering Attack", "IoT-Based Attack",
    "Physical Attack"
]

def print_banner():
    print("\n".join(banner_wva))

def ask_for_attack_choice(num_vulns):
    while True:
        try:
            choice = int(input(f"{BLUE}Enter the number of vulnerability to attack (1-{num_vulns}, 0 to skip): {ENDC}").strip())
            if 0 <= choice <= num_vulns:
                return choice
            else:
                print(f"{RED}Invalid choice. Please enter a number between 0 and {num_vulns}.{ENDC}")
        except ValueError:
            print(f"{RED}Invalid input. Please enter a number.{ENDC}")

def attack(target, service):
    print(f"{BLUE}Attacking {service} service on {target}...{ENDC}")
    # Example: Implement actual attack code here
    time.sleep(1)  # Simulating attack delay
    subprocess.run([service, target])

def simulate_scan(target):
    # Simulating deep scan
    print(f"{BLUE}Performing deep scan on {target}...{ENDC}")
    time.sleep(2)  # Simulate scanning delay
    vulnerabilities = random.sample(attack_types, k=random.randint(1, len(attack_types)))
    return vulnerabilities

def display_system_info():
    # Simulating displaying system info
    print(f"{BLUE}Fetching system information...{ENDC}")
    time.sleep(1)
    # Example: Fetch and display system info (OS, open ports, users, passwords)
    os_info = subprocess.check_output(['uname', '-a']).decode().strip()
    open_ports = subprocess.check_output(['netstat', '-tuln']).decode().strip()
    users = subprocess.check_output(['who']).decode().strip()
    passwords = subprocess.check_output(['cat', '/etc/passwd']).decode().strip()
    print(f"{BLUE}System Information:")
    print(f"  - OS: {os_info}")
    print(f"  - Open Ports:\n{open_ports}")
    print(f"  - Users:\n{users}")
    print(f"  - Passwords:\n{passwords}{ENDC}")

def main():
    parser = argparse.ArgumentParser(description="Web Vulnerabilities Analyzer (WVA)")
    parser.add_argument("--wizard", action="store_true", help="Run WVA wizard to scan for vulnerabilities and open ports")

    args = parser.parse_args()

    if args.wizard:
        print_banner()
        target = input(f"{BLUE}Enter target hostname or IP address: {ENDC}").strip()

        vulnerabilities = simulate_scan(target)
        num_vulns = len(vulnerabilities)

        if num_vulns > 0:
            print(f"{RED}Detected vulnerabilities:{ENDC}")
            for i, vulnerability in enumerate(vulnerabilities, 1):
                print(f"{RED} {i}. {vulnerability}{ENDC}")

            attack_choice = ask_for_attack_choice(num_vulns)
            if attack_choice > 0:
                attack(target, random.choice(available_services))
            else:
                print(f"{GOLD}Skipping attack.{ENDC}")

        else:
            print(f"{GOLD}No vulnerabilities detected on {target}.{ENDC}")

        display_system_info()

    else:
        print(f"{RED}Please use --wizard option to run the WVA wizard.{ENDC}")

if __name__ == "__main__":
    if not sys.platform.startswith("linux"):
        print(f"{RED}This tool is designed to run on Linux. Exiting.{ENDC}")
        sys.exit(1)
    if os.geteuid() != 0:
        print(f"{RED}Please run this script as root to access all features.{ENDC}")
        sys.exit(1)

    main()
