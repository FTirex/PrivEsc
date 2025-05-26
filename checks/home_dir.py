# checks/home_dir_permissions_check.py

import os
import stat # For checking file modes

def check_home_directory_permissions():
    """
    Checks for weak permissions on the current user's home directory
    and the .ssh directory, with a focus on authorized_keys.
    """
    print("[*] Checking home directory and SSH key permissions...")

    home_dir = os.path.expanduser("~") # Get current user's home directory
    ssh_dir = os.path.join(home_dir, ".ssh")
    authorized_keys_path = os.path.join(ssh_dir, "authorized_keys")

    found_weak_permissions = False
    
    # --- Check Home Directory Permissions ---
    if os.path.exists(home_dir):
        try:
            home_dir_stat = os.stat(home_dir)
            # Home directory should not be group-writable or world-writable.
            # Recommended: 755 (drwxr-xr-x) or 700 (drwx------)
            if bool(home_dir_stat.st_mode & stat.S_IWGRP) or \
               bool(home_dir_stat.st_mode & stat.S_IWOTH):
                print(f"  [+] WARNING: Home directory '{home_dir}' has weak permissions: {oct(home_dir_stat.st_mode)[-4:]}")
                print("      Group or others have write permissions. This could allow unauthorized access or modification.")
                found_weak_permissions = True
        except Exception as e:
            print(f"  [!] Could not check home directory permissions for '{home_dir}': {e}")
    else:
        print(f"  [!] Warning: Home directory '{home_dir}' not found.")

    # --- Check .ssh Directory Permissions ---
    if os.path.exists(ssh_dir) and os.path.isdir(ssh_dir):
        try:
            ssh_dir_stat = os.stat(ssh_dir)
            # .ssh directory should ideally be 700 (drwx------)
            # It must not be writable by others or group.
            if bool(ssh_dir_stat.st_mode & (stat.S_IRWXG | stat.S_IRWXO)):
                print(f"  [+] WARNING: '.ssh' directory '{ssh_dir}' has weak permissions: {oct(ssh_dir_stat.st_mode)[-4:]}")
                print("      Group or others have read/write/execute permissions. This is a significant security risk for SSH access.")
                found_weak_permissions = True
        except Exception as e:
            print(f"  [!] Could not check .ssh directory permissions for '{ssh_dir}': {e}")
            
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
                        # Should be 600 (rw-------) or 644 for public parts of keys, but 600 is safest for private.
                        # Check for any group/other permissions
                        if bool(file_stat.st_mode & (stat.S_IRWXG | stat.S_IRWXO)):
                            print(f"    [+] WARNING: SSH file '{filepath}' has weak permissions: {file_mode_oct}")
                            print("        Group or others have read/write/execute permissions. Immediate security risk for SSH credentials!")
                            found_weak_permissions = True
                    elif filename == "authorized_keys":
                        # authorized_keys can be 600 (rw-------) or 644 (rw-r--r--)
                        # It must NOT be group-writable or world-writable.
                        if bool(file_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_IXGRP | stat.S_IXOTH)):
                            print(f"    [+] WARNING: 'authorized_keys' file '{filepath}' has weak permissions: {file_mode_oct}")
                            print("        Group or others have write/execute permissions. This is a severe security risk, allowing unauthorized key injection!")
                            found_weak_permissions = True
                        
                        # Check if authorized_keys contains suspicious entries (basic check)
                        # This is a very basic check for common "commands" options or specific, known bad patterns.
                        try:
                            with open(filepath, 'r') as f:
                                for line_num, line in enumerate(f, 1):
                                    line = line.strip()
                                    if line.startswith("command=") or line.startswith("no-port-forwarding") or \
                                       line.startswith("no-X11-forwarding") or line.startswith("no-agent-forwarding") or \
                                       line.startswith("no-pty"):
                                        print(f"    [!] NOTE: 'authorized_keys' ({filepath}:{line_num}) contains SSH options: '{line}'")
                                        print("        Review this line. While some options are valid, misconfigured 'command=' can be exploited.")
                                    # Add more checks for suspicious patterns like "from=" or specific IP ranges
                                    # For example, look for widely open 'from="*"'
                                    if 'from="' in line and '"*"' in line:
                                        print(f"    [!] NOTE: 'authorized_keys' ({filepath}:{line_num}) has 'from=\"*\"': '{line}'")
                                        print("        This allows connections from any host, which might be overly permissive.")
                        except Exception as read_err:
                            print(f"    [!] Could not read 'authorized_keys' file '{filepath}': {read_err}")

                except Exception as e:
                    print(f"    [!] Could not check SSH file {filepath} permissions: {e}")
    else:
        # print(f"  [-] '.ssh' directory '{ssh_dir}' not found or not a directory.")
        pass # Not a vulnerability if .ssh doesn't exist

    if not found_weak_permissions:
        print("  [-] Home directory and SSH key permissions are generally good.")
    
    print("-" * 40)

# Optional: Test the module independently
if __name__ == "__main__":
    check_home_directory_permissions()