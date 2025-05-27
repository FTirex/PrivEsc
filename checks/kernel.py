# checks/kernel_version_check.py

import subprocess
from utils.findings import findings_collector, Severity

def check_kernel_version():
    """
    Retrieves the kernel version and advises on checking for known exploits.
    """
    print("[*] Checking kernel version for known vulnerabilities...")
    try:
        result = subprocess.run(['uname', '-a'], capture_output=True, text=True, check=True)
        kernel_info = result.stdout.strip()
        kernel_version = kernel_info.split(' ')[2]

        findings_collector.add_finding(
            check_type="Kernel Version",
            severity=Severity.INFO, # This is INFO, as it only identifies, not confirms vulnerability
            title="Kernel Version Identified",
            description=f"The current Linux kernel version is: {kernel_version}",
            details=f"Full uname output: {kernel_info}",
            recommendation="Research this kernel version (e.g., on Exploit-DB, Google, CVE databases) for known local privilege escalation (LPE) exploits. Pay attention to the exact version and distribution."
        )

    except FileNotFoundError:
        findings_collector.add_finding(
            check_type="Kernel Version",
            severity=Severity.LOW,
            title="'uname' Command Not Found",
            description="The 'uname' command is not found. Cannot determine kernel version.",
            recommendation="Ensure 'coreutils' or similar basic system tools are installed."
        )
    except subprocess.CalledProcessError as e:
        findings_collector.add_finding(
            check_type="Kernel Version",
            severity=Severity.LOW,
            title="Error Running 'uname -a'",
            description=f"Error executing 'uname -a': {e.stderr.strip()}",
            recommendation="Review the error for potential debugging."
        )
    except Exception as e:
        findings_collector.add_finding(
            check_type="Kernel Version",
            severity=Severity.LOW,
            title="Unexpected Error During Kernel Version Check",
            description=f"An unexpected error occurred: {e}",
            recommendation="Review the error for potential debugging."
        )
    print("-" * 40)

# Optional: Test the module independently
if __name__ == "__main__":
    check_kernel_version()