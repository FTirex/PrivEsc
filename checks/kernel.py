# checks/kernel_version_check.py

import subprocess

def check_kernel_version():
    """
    Retrieves the kernel version and advises on checking for known exploits.
    """
    print("[*] Checking kernel version for known vulnerabilities...")
    try:
        # Run 'uname -a' to get detailed kernel information
        result = subprocess.run(['uname', '-a'], capture_output=True, text=True, check=True)
        kernel_info = result.stdout.strip()
        
        # Extract just the kernel version (e.g., '5.4.0-77-generic')
        # This is a basic attempt; more robust parsing might be needed for specific formats.
        kernel_version = kernel_info.split(' ')[2]

        print(f"  [+] Current Kernel Version: {kernel_version}")
        print("      ACTION: Research this kernel version on Exploit-DB, Google, or CVE databases.")
        print("      Look for local privilege escalation (LPE) exploits specific to this version.")
        print(f"      Full uname output: {kernel_info}")

    except FileNotFoundError:
        print("  [!] 'uname' command not found. Cannot determine kernel version.")
    except subprocess.CalledProcessError as e:
        print(f"  [!] Error running 'uname -a': {e.stderr.strip()}")
    except Exception as e:
        print(f"  [!] An unexpected error occurred during kernel version check: {e}")
    print("-" * 40)

# Optional: Test the module independently
if __name__ == "__main__":
    check_kernel_version()