# checks/sudo_checks.py

import subprocess
import os # We'll need os for DEVNULL

def check_sudo_misconfigurations():
    """
    Checks for sudo misconfigurations by running 'sudo -l'.
    Looks for entries that allow the current user to run commands as root without a password.
    """
    print("[*] Checking for SUDO misconfigurations...")
    try:
        # Run 'sudo -l' to list allowed sudo commands for the current user.
        # Fixed: Using stdout=subprocess.PIPE and stderr=subprocess.DEVNULL
        # instead of capture_output=True to avoid ValueError.
        result = subprocess.run(
            ['sudo', '-l'],
            stdout=subprocess.PIPE,  # Capture standard output
            stderr=subprocess.DEVNULL, # Send standard error to nowhere (discard it)
            text=True,               # Decode output as text
            check=True               # Raise an exception for non-zero exit codes
        )
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
        # Note: e.stderr might be empty here because we redirected stderr to DEVNULL.
        # This catch is mostly for when `check=True` fails due to command not found or other non-permission errors
        # that still exit with a non-zero code but don't output to stderr.
        if "User is not in the sudoers file" in e.output: # Sometimes this info comes on stdout
            print("  [-] Current user is not in the sudoers file or cannot run sudo commands.")
        else:
            # If there's an error, but it's not the "not in sudoers" one, print generic error.
            print(f"  [!] Error running 'sudo -l'. Command returned non-zero exit code.")
            print(f"      Stdout (if any): {e.stdout.strip()}")
            # We explicitly send stderr to DEVNULL, so e.stderr will be empty.
            print(f"      Consider checking if sudo is installed and accessible.")
    except FileNotFoundError:
        print("  [!] 'sudo' command not found. Is sudo installed on this system?")
    except Exception as e: # Catch any other unexpected errors
        print(f"  [!] An unexpected error occurred: {e}")
    print("-" * 40)

# Example of how you could test this module independently (optional)
if __name__ == "__main__":
    check_sudo_misconfigurations()