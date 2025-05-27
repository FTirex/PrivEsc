# checks/writable_files_checks.py

import os
from utils.findings import findings_collector, Severity

def check_writable_critical_files():
    """
    Checks if /etc/passwd or /etc/shadow are writable by the current user.
    """
    print("[*] Checking for writable /etc/passwd or /etc/shadow...")

    critical_files = ["/etc/passwd", "/etc/shadow"]
    found_writable = False

    for filepath in critical_files:
        if os.path.exists(filepath):
            if os.access(filepath, os.W_OK):
                findings_collector.add_finding(
                    check_type="Writable Critical Files",
                    severity=Severity.CRITICAL,
                    title=f"CRITICAL: '{filepath}' is Writable!",
                    description=f"The file '{filepath}' is writable by the current user.",
                    recommendation=f"This is a severe misconfiguration. You can directly add a new root user or modify existing user's password hash within '{filepath}' (e.g., using `mkpasswd` or `openssl passwd` to generate a hash for '/etc/passwd')."
                )
                found_writable = True
        else:
            findings_collector.add_finding(
                check_type="Writable Critical Files",
                severity=Severity.INFO,
                title=f"Critical File Not Found: '{filepath}'",
                description=f"The critical system file '{filepath}' was not found. This is unusual.",
                recommendation="Verify the existence of this file and the system's configuration."
            )

    if not found_writable:
        print("  [-] /etc/passwd and /etc/shadow are not writable by the current user (Good).")
    
    print("-" * 40)

# Optional: Test the module independently
if __name__ == "__main__":
    check_writable_critical_files()