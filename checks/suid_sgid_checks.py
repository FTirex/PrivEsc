# checks/suid_sgid_checks.py

import subprocess
import os
from utils.findings import findings_collector, Severity

def check_suid_sgid_binaries():
    """
    Identifies SUID and SGID binaries that could potentially be exploited.
    Uses the 'find' command to locate these files.
    """
    print("[*] Checking for SUID/SGID binaries...")

    search_paths = [
        '/bin', '/usr/bin', '/sbin', '/usr/sbin',
        '/usr/local/bin', '/usr/local/sbin'
    ]

    found_potential_binaries = False

    for path in search_paths:
        if not os.path.isdir(path):
            continue

        try:
            find_command = ['find', path, '-perm', '/4000', '-o', '-perm', '/2000', '-type', 'f', '-print0']
            
            process = subprocess.Popen(find_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()

            if process.returncode != 0:
                if "Permission denied" in stderr.decode(errors='ignore'):
                    print(f"  [!] Permission denied when searching in {path}. Some SUID/SGID results might be missing.")
                else:
                    print(f"  [!] Error running find in {path}: {stderr.decode(errors='ignore').strip()}")
                continue
            
            files = stdout.decode(errors='ignore').strip('\0').split('\0')
            files = [f for f in files if f]

            for found_file in files:
                try:
                    stat_info = os.stat(found_file)
                    mode = stat_info.st_mode
                    is_suid = bool(mode & 0o4000)
                    is_sgid = bool(mode & 0o2000)
                    perm_str = oct(mode)[-4:]
                    
                    if is_suid or is_sgid:
                        title = f"SUID/SGID Binary Found: {os.path.basename(found_file)}"
                        description = f"The executable '{found_file}' has SUID (run as owner) or SGID (run as group) permissions set."
                        details = f"Permissions: {perm_str}, SUID: {is_suid}, SGID: {is_sgid}"
                        recommendation = "Investigate this binary on resources like GTFOBins (gtfobins.github.io) to check for known exploits or misconfigurations. Common examples include `find`, `nmap`, `vim`, `less`."
                        
                        # Assign severity based on common exploitability, or default to Medium
                        severity = Severity.MEDIUM
                        if any(b in found_file for b in ["/usr/bin/find", "/usr/bin/nmap", "/usr/bin/vim", "/usr/bin/less", "/usr/bin/bash", "/usr/bin/awk", "/usr/bin/more"]):
                            severity = Severity.HIGH

                        findings_collector.add_finding(
                            check_type="SUID/SGID Binaries",
                            severity=severity,
                            title=title,
                            description=description,
                            details=details,
                            recommendation=recommendation
                        )
                        found_potential_binaries = True
                except FileNotFoundError:
                    pass # File might have been deleted between find and os.stat
                except Exception as e:
                    print(f"  [!] Could not stat file {found_file}: {e}")


        except FileNotFoundError:
            findings_collector.add_finding(
                check_type="SUID/SGID Binaries",
                severity=Severity.LOW,
                title="'find' Command Not Found",
                description="The 'find' command is essential for this check but was not found.",
                recommendation="Ensure 'find' is installed on the system."
            )
            break
        except Exception as e:
            findings_collector.add_finding(
                check_type="SUID/SGID Binaries",
                severity=Severity.LOW,
                title="Unexpected Error During SUID/SGID Check",
                description=f"An unexpected error occurred: {e}",
                recommendation="Review the error for potential debugging."
            )
            
    if not found_potential_binaries:
        print("  [-] No SUID/SGID binaries found in common paths that are typically easily exploitable.")

    print("-" * 40)

# Optional: Test the module independently
if __name__ == "__main__":
    check_suid_sgid_binaries()