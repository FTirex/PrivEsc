# checks/sudo_checks.py

import subprocess

def check_sudo_misconfigurations():
    """
    Checks for sudo misconfigurations by running 'sudo -l'.
    Looks for entries that allow the current user to run commands as root without a password.
    """
    print("[*] Checking for SUDO misconfigurations...")
    try:
        # Run 'sudo -l' to list allowed sudo commands for the current user.
        # The 'NOPASSWD' flag is often a sign of a misconfiguration.
        # We redirect stderr to devnull to suppress potential errors like "sudo: no tty present..."
        result = subprocess.run(['sudo', '-l'], capture_output=True, text=True, check=True, stderr=subprocess.DEVNULL)
        output = result.stdout

        found_misconfigurations = False
        for line in output.splitlines():
            # Look for lines indicating NOPASSWD or ALL commands for the current user
            # This is a basic check; more advanced parsing might be needed for complex rules.
            if "NOPASSWD" in line and "ALL" in line and "ALL" in line.split(' (')[0]:
                print(f"  [+] Possible SUDO NOPASSWD misconfiguration found:")
                print(f"      {line.strip()}")
                print("      Consider investigating if you can run privileged commands without a password.")
                found_misconfigurations = True
            elif "ALL" in line and "(ALL:ALL)" in line:
                print(f"  [+] Possible SUDO ALL commands misconfiguration found:")
                print(f"      {line.strip()}")
                print("      Consider investigating if you can run any command as any user/group.")
                found_misconfigurations = True

        if not found_misconfigurations:
            print("  [-] No obvious SUDO misconfigurations found for the current user based on 'sudo -l'.")

    except subprocess.CalledProcessError as e:
        if "User is not in the sudoers file" in e.stderr:
            print("  [-] Current user is not in the sudoers file or cannot run sudo commands.")
        else:
            print(f"  [!] Error running 'sudo -l': {e.stderr.strip()}")
            print(f"      Consider checking if sudo is installed and accessible.")
    except FileNotFoundError:
        print("  [!] 'sudo' command not found. Is sudo installed on this system?")
    print("-" * 40)

# Example of how you could test this module independently (optional)
if __name__ == "__main__":
    check_sudo_misconfigurations()