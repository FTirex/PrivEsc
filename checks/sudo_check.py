# checks/sudo_checks.py

import subprocess
import os
from utils.findings import findings_collector, Severity

def check_sudo_misconfigurations():
    """
    Checks for sudo misconfigurations by running 'sudo -l'.
    Looks for entries that allow the current user to run commands as root without a password.
    """
    print("[*] Checking for SUDO misconfigurations...")
    try:
        result = subprocess.run(
            ['sudo', '-l'],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=True
        )
        output = result.stdout

        found_misconfigurations = False
        for line in output.splitlines():
            if "NOPASSWD" in line and "ALL" in line and "ALL" in line.split(' (')[0]:
                findings_collector.add_finding(
                    check_type="SUDO Misconfiguration",
                    severity=Severity.HIGH,
                    title="SUDO NOPASSWD Entry Found",
                    description="The current user can run certain commands as root without a password.",
                    details=f"Relevant line: {line.strip()}",
                    recommendation="Investigate the allowed commands. If they include 'ALL' or critical binaries (e.g., 'vi', 'find', 'less', 'nmap'), you can likely escalate privileges."
                )
                found_misconfigurations = True
            elif "ALL" in line and "(ALL:ALL)" in line:
                findings_collector.add_finding(
                    check_type="SUDO Misconfiguration",
                    severity=Severity.CRITICAL,
                    title="SUDO ALL Commands Allowed",
                    description="The current user can run any command as any user/group without restriction.",
                    details=f"Relevant line: {line.strip()}",
                    recommendation="This is a direct path to root. You can typically run `sudo su -` or `sudo /bin/bash`."
                )
                found_misconfigurations = True

        if not found_misconfigurations:
            print("  [-] No obvious SUDO misconfigurations found for the current user based on 'sudo -l'.")

    except subprocess.CalledProcessError as e:
        if "User is not in the sudoers file" in e.output:
            print("  [-] Current user is not in the sudoers file or cannot run sudo commands.")
        else:
            findings_collector.add_finding(
                check_type="SUDO Misconfiguration",
                severity=Severity.LOW,
                title="Error Checking SUDO Permissions",
                description="Could not determine sudo permissions. 'sudo -l' returned an error.",
                details=f"Error message: {e.stdout.strip()}",
                recommendation="Ensure sudo is installed and you have basic permissions to run `sudo -l` (even if it's denied)."
            )
    except FileNotFoundError:
        findings_collector.add_finding(
            check_type="SUDO Misconfiguration",
            severity=Severity.LOW,
            title="'sudo' Command Not Found",
            description="The 'sudo' command was not found on the system.",
            recommendation="Verify if 'sudo' is installed. If not, this vector is unavailable."
        )
    except Exception as e:
        findings_collector.add_finding(
            check_type="SUDO Misconfiguration",
            severity=Severity.LOW,
            title="Unexpected Error During SUDO Check",
            description=f"An unexpected error occurred: {e}",
            recommendation="Review the error for potential debugging."
        )
    print("-" * 40)

# Example of how you could test this module independently (optional)
if __name__ == "__main__":
    check_sudo_misconfigurations()