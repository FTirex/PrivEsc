# checks/home_dir_permissions_check.py

import os
import stat
from utils.findings import findings_collector, Severity

def check_home_directory_permissions():
    """
    Checks for weak permissions on the current user's home directory
    and the .ssh directory, with a focus on authorized_keys.
    """
    print("[*] Checking home directory and SSH key permissions...")

    home_dir = os.path.expanduser("~")
    ssh_dir = os.path.join(home_dir, ".ssh")
    
    # --- Check Home Directory Permissions ---
    if os.path.exists(home_dir):
        try:
            home_dir_stat = os.stat(home_dir)
            if bool(home_dir_stat.st_mode & stat.S_IWGRP) or \
               bool(home_dir_stat.st_mode & stat.S_IWOTH):
                findings_collector.add_finding(
                    check_type="Weak Home Directory Permissions",
                    severity=Severity.MEDIUM,
                    title="Home Directory is Writable by Others",
                    description=f"The home directory '{home_dir}' has weak permissions (Mode: {oct(home_dir_stat.st_mode)[-4:]}).",
                    details="Group or others have write permissions.",
                    recommendation="Ensure your home directory is not writable by group or others (e.g., permissions 755 or 700). This could allow other users to plant malicious files or access sensitive data."
                )
        except Exception as e:
            findings_collector.add_finding(
                check_type="Weak Home Directory Permissions",
                severity=Severity.LOW,
                title="Error Checking Home Directory Permissions",
                description=f"Could not check home directory permissions for '{home_dir}'.",
                details=f"Error: {e}",
                recommendation="Review the error for potential debugging."
            )
    else:
        findings_collector.add_finding(
            check_type="Weak Home Directory Permissions",
            severity=Severity.INFO,
            title="Home Directory Not Found",
            description=f"The home directory '{home_dir}' was not found. This is unexpected.",
            recommendation="Verify the system's home directory configuration."
        )

    # --- Check .ssh Directory Permissions ---
    if os.path.exists(ssh_dir) and os.path.isdir(ssh_dir):
        try:
            ssh_dir_stat = os.stat(ssh_dir)
            if bool(ssh_dir_stat.st_mode & (stat.S_IRWXG | stat.S_IRWXO)):
                findings_collector.add_finding(
                    check_type="Weak SSH Directory Permissions",
                    severity=Severity.HIGH,
                    title="'.ssh' Directory Has Weak Permissions",
                    description=f"The '.ssh' directory '{ssh_dir}' has weak permissions (Mode: {oct(ssh_dir_stat.st_mode)[-4:]}).",
                    details="Group or others have read/write/execute permissions.",
                    recommendation="Ensure the '.ssh' directory permissions are 700 (drwx------) to prevent unauthorized access to SSH keys and configurations."
                )
        except Exception as e:
            findings_collector.add_finding(
                check_type="Weak SSH Directory Permissions",
                severity=Severity.LOW,
                title="Error Checking .ssh Directory Permissions",
                description=f"Could not check .ssh directory permissions for '{ssh_dir}'.",
                details=f"Error: {e}",
                recommendation="Review the error for potential debugging."
            )
            
        # --- Check individual SSH key files (including authorized_keys) ---
        ssh_files_to_check = [
            "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", # Private keys
            "authorized_keys",                             # Public keys (critical for access)
            "config"                                       # SSH config file (often sensitive)
        ]

        for filename in ssh_files_to_check:
            filepath = os.path.join(ssh_dir, filename)
            if os.path.exists(filepath) and os.path.isfile(filepath):
                try:
                    file_stat = os.stat(filepath)
                    file_mode_oct = oct(file_stat.st_mode)[-4:]

                    if "id_" in filename or filename == "config": # Private keys and config
                        if bool(file_stat.st_mode & (stat.S_IRWXG | stat.S_IRWXO)):
                            findings_collector.add_finding(
                                check_type="Weak SSH Key/Config Permissions",
                                severity=Severity.CRITICAL,
                                title=f"Private SSH Key/Config File '{filename}' Has Weak Permissions",
                                description=f"The file '{filepath}' has weak permissions (Mode: {file_mode_oct}).",
                                details="Group or others have read/write/execute permissions.",
                                recommendation="Immediately correct permissions to 600 (rw-------) for private keys and config files to prevent unauthorized access to credentials."
                            )
                    elif filename == "authorized_keys":
                        if bool(file_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_IXGRP | stat.S_IXOTH)):
                            findings_collector.add_finding(
                                check_type="Weak SSH Authorized Keys Permissions",
                                severity=Severity.HIGH,
                                title="'authorized_keys' File Has Weak Permissions",
                                description=f"The file '{filepath}' has weak permissions (Mode: {file_mode_oct}).",
                                details="Group or others have write/execute permissions.",
                                recommendation="Ensure 'authorized_keys' permissions are 600 or 644. Write permissions for others allows unauthorized key injection, leading to direct SSH access."
                            )
                        
                        # Check authorized_keys content for suspicious entries
                        try:
                            with open(filepath, 'r') as f:
                                for line_num, line in enumerate(f, 1):
                                    line = line.strip()
                                    if line.startswith("command=") or line.startswith("no-port-forwarding") or \
                                       line.startswith("no-X11-forwarding") or line.startswith("no-agent-forwarding") or \
                                       line.startswith("no-pty"):
                                        findings_collector.add_finding(
                                            check_type="SSH Authorized Keys Content",
                                            severity=Severity.INFO,
                                            title="SSH Authorized Key Line with Options Detected",
                                            description=f"A line in '{filepath}' contains SSH options (e.g., command=, no-X11-forwarding).",
                                            details=f"Line {line_num}: '{line}'",
                                            recommendation="Review this line. While legitimate, 'command=' options with vulnerable scripts can be exploited for privilege escalation."
                                        )
                                    if 'from="' in line and '"*"' in line:
                                        findings_collector.add_finding(
                                            check_type="SSH Authorized Keys Content",
                                            severity=Severity.MEDIUM,
                                            title="Overly Permissive 'from=\"*\"' in Authorized Keys",
                                            description=f"A line in '{filepath}' uses 'from=\"*\"' allowing connections from any host.",
                                            details=f"Line {line_num}: '{line}'",
                                            recommendation="Restrict `from=` options to specific IP addresses or networks if possible. This is not a direct PE, but reduces the attack surface."
                                        )
                        except Exception as read_err:
                            findings_collector.add_finding(
                                check_type="SSH Authorized Keys Content",
                                severity=Severity.LOW,
                                title="Error Reading Authorized Keys",
                                description=f"Could not read 'authorized_keys' file '{filepath}'.",
                                details=f"Error: {read_err}",
                                recommendation="Verify file readability for analysis."
                            )

                except Exception as e:
                    findings_collector.add_finding(
                        check_type="Weak SSH Key/Config Permissions",
                        severity=Severity.LOW,
                        title=f"Error Checking SSH File Permissions: '{filepath}'",
                        description=f"Could not check permissions for '{filepath}'.",
                        details=f"Error: {e}",
                        recommendation="Review the error for potential debugging."
                    )
    else:
        print(f"  [-] '.ssh' directory '{ssh_dir}' not found or not a directory. (No SSH keys to check here)")
    
    print("-" * 40)

# Optional: Test the module independently
if __name__ == "__main__":
    check_home_directory_permissions()