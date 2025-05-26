# checks/writable_files_checks.py

import os

def check_writable_critical_files():
    """
    Checks if /etc/passwd or /etc/shadow are writable by the current user.
    """
    print("[*] Checking for writable /etc/passwd or /etc/shadow...")

    critical_files = ["/etc/passwd", "/etc/shadow"]
    found_writable = False

    for filepath in critical_files:
        if os.path.exists(filepath):
            # Check if the current user has write permissions for the file
            # os.access(path, mode) returns True if access is granted, False otherwise.
            # os.W_OK checks for write access.
            if os.access(filepath, os.W_OK):
                print(f"  [+] CRITICAL: '{filepath}' is writable by the current user!")
                print(f"      This is a severe misconfiguration that could allow direct privilege escalation.")
                found_writable = True
            # else:
                # print(f"  [-] '{filepath}' is not writable by the current user (Good).")
        # else:
            # print(f"  [!] Warning: '{filepath}' not found.") # Should always exist on Linux

    if not found_writable:
        print("  [-] /etc/passwd and /etc/shadow are not writable by the current user (Good).")
    
    print("-" * 40)

# Optional: Test the module independently
if __name__ == "__main__":
    check_writable_critical_files()