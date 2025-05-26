# privesc_checker.py

import os
import subprocess
from checks.sudo_check import check_sudo_misconfigurations
from checks.writable_files import check_writable_critical_files
from checks.kernel import check_kernel_version
from checks.home_dir import check_home_directory_permissions
from checks.advanced_checks import run_all_advanced_checks # New import

def print_banner():
    """Prints a simple banner for the tool."""
    print("=" * 50)
    print("  Linux Privilege Escalation Checker  ")
    print("=" * 50)
    print("\nScanning for potential privilege escalation vectors...\n")

def main():
    """Main function to orchestrate the vulnerability checks."""
    print_banner()

    # Call the check functions from their respective modules
    check_sudo_misconfigurations()
    check_writable_critical_files()
    check_kernel_version()
    check_home_directory_permissions()
    
    # Call the new advanced checks
    run_all_advanced_checks()

    print("\nScan complete. Review the findings above.")

if __name__ == "__main__":
    main()