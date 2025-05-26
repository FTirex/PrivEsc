# privesc_checker.py

import os
import subprocess
from checks.sudo_check import check_sudo_misconfigurations # Import module from checks folder 

def print_banner():
    """Prints a simple banner for the tool."""
    print("=" * 50)
    print("  Linux Privilege Escalation Checker  ")
    print("=" * 50)
    print("\nScanning for potential privilege escalation vectors...\n")

def main():
    """Main function to orchestrate the vulnerability checks."""
    print_banner()

    # Call the check function from the sudo_checks module
    check_sudo_misconfigurations()

    # We will add more check functions here later

    print("\nScan complete. Review the findings above.")

if __name__ == "__main__":
    main()