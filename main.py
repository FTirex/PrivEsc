# privesc_checker.py

import os
import subprocess
from checks.sudo_check import check_sudo_misconfigurations
from checks.suid_sgid_checks import check_suid_sgid_binaries
from checks.writable_files import check_writable_critical_files
from checks.kernel import check_kernel_version
from checks.home_dir import check_home_directory_permissions
from checks.advanced_checks import run_all_advanced_checks

from utils.findings import findings_collector # Import the collector

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
    check_suid_sgid_binaries()
    check_writable_critical_files()
    check_kernel_version()
    check_home_directory_permissions()
    run_all_advanced_checks() # This function now internally uses findings_collector

    print("\nScan complete. Generating summary and recommendations...\n")
    findings_collector.print_summary() # Print the summarized findings

if __name__ == "__main__":
    main()