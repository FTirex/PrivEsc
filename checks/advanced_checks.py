# checks/advanced_checks.py

import os
import subprocess
import stat
from utils.findings import findings_collector, Severity

def run_command(command, suppress_errors=False, check_return=False):
    """Helper function to run a shell command and return stdout."""
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=check_return,
            errors='ignore',
            stderr=subprocess.DEVNULL if suppress_errors else None
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        if not suppress_errors:
            # print(f"  [!] Error running command '{' '.join(command)}': {e.stderr.strip()}")
            pass
        return ""
    except FileNotFoundError:
        if not suppress_errors:
            print(f"  [!] Command not found: '{command[0]}'")
        return ""
    except Exception as e:
        if not suppress_errors:
            print(f"  [!] An unexpected error occurred with command '{' '.join(command)}': {e}")
        return ""

def is_writable_by_current_user(filepath):
    """Checks if a file is writable by the current user."""
    return os.path.exists(filepath) and os.access(filepath, os.W_OK)

def is_readable_by_others(filepath):
    """Checks if a file is readable by 'others' (world-readable)."""
    if os.path.exists(filepath):
        try:
            mode = os.stat(filepath).st_mode
            return bool(mode & stat.S_IROTH)
        except Exception:
            return False
    return False

def check_environment_variables():
    """
    Checks for potential environment variable exploits (PATH, LD_PRELOAD).
    This is mostly informational and suggests manual checks.
    """
    print("[*] Checking for environment variable vulnerabilities (PATH, LD_PRELOAD)...")

    path_env = os.getenv('PATH')
    if path_env:
        path_dirs = path_env.split(':')
        for p_dir in path_dirs:
            if os.path.isdir(p_dir) and is_writable_by_current_user(p_dir):
                findings_collector.add_finding(
                    check_type="Environment Variable - PATH",
                    severity=Severity.MEDIUM,
                    title="Writable PATH Directory Detected",
                    description=f"A directory in the current user's PATH ('{p_dir}') is writable by the current user.",
                    recommendation="This could allow injection of malicious executables. If a privileged process executes a command (e.g., 'ls') without its absolute path, your malicious 'ls' might be run instead if '{p_dir}' appears earlier in the PATH."
                )
        
    ld_preload_env = os.getenv('LD_PRELOAD')
    if ld_preload_env:
        findings_collector.add_finding(
            check_type="Environment Variable - LD_PRELOAD",
            severity=Severity.MEDIUM,
            title="LD_PRELOAD Environment Variable Set",
            description=f"The LD_PRELOAD environment variable is set to: {ld_preload_env}.",
            recommendation="While legitimate, this could be used to inject malicious libraries. If a privileged SUID/SGID binary is vulnerable to LD_PRELOAD, it's a critical path. Investigate if the library is legitimate or if you can control its content."
        )

    suspicious_envs = ['LD_LIBRARY_PATH', 'IFS', 'PS1', 'BASH_ENV']
    for env_var in suspicious_envs:
        val = os.getenv(env_var)
        if val:
            findings_collector.add_finding(
                check_type="Environment Variable",
                severity=Severity.LOW,
                title=f"Suspicious Environment Variable '{env_var}' Set",
                description=f"The environment variable '{env_var}' is set to: {val}.",
                recommendation=f"Consider if this variable can be manipulated to influence program execution or shell behavior for privilege escalation."
            )
    
    print("-" * 40)


def check_cron_job_misconfigurations():
    """
    Checks for cron jobs that are potentially exploitable due to weak permissions
    on scripts they execute or the cron directories themselves.
    """
    print("[*] Checking for cron job misconfigurations...")
    
    # Check /etc/cron.d/ for writable files
    cron_d_path = "/etc/cron.d"
    if os.path.isdir(cron_d_path):
        try:
            for filename in os.listdir(cron_d_path):
                filepath = os.path.join(cron_d_path, filename)
                if os.path.isfile(filepath) and is_writable_by_current_user(filepath):
                    findings_collector.add_finding(
                        check_type="Cron Job Misconfiguration",
                        severity=Severity.CRITICAL,
                        title=f"Writable Cron File in '/etc/cron.d': '{filepath}'",
                        description=f"A cron job definition file in '/etc/cron.d' is writable by the current user.",
                        recommendation="This allows direct modification of system-wide cron jobs. You can inject commands to be executed as root by modifying this file."
                    )
        except PermissionError:
            print(f"  [!] Permission denied when accessing '{cron_d_path}'. Cannot check for writable cron.d files.")
        except Exception as e:
            print(f"  [!] Error checking '{cron_d_path}': {e}")


    # Check /var/spool/cron/crontabs for writable user crontabs (less direct for root)
    crontabs_path = "/var/spool/cron/crontabs"
    if os.path.isdir(crontabs_path):
        try:
            for username_file in os.listdir(crontabs_path):
                filepath = os.path.join(crontabs_path, username_file)
                if os.path.isfile(filepath) and is_writable_by_current_user(filepath):
                    findings_collector.add_finding(
                        check_type="Cron Job Misconfiguration",
                        severity=Severity.LOW,
                        title=f"User Crontab File Writable: '{filepath}'",
                        description=f"A user's crontab file ('{filepath}') is writable. While a user can usually modify their own crontab, investigate if this belongs to an admin user or if the file permissions are overly lax for other users.",
                        recommendation="If this is an admin user's crontab and it's writable by a lower-privileged user, it could be an escalation path. Otherwise, it's typically normal."
                    )
        except PermissionError:
            print(f"  [!] Permission denied when accessing '{crontabs_path}'. Cannot check for writable user crontabs.")
        except Exception as e:
            print(f"  [!] Error checking '{crontabs_path}': {e}")


    # Check if the /etc/crontab file itself is writable
    etc_crontab = "/etc/crontab"
    if os.path.exists(etc_crontab):
        if is_writable_by_current_user(etc_crontab):
            findings_collector.add_finding(
                check_type="Cron Job Misconfiguration",
                severity=Severity.CRITICAL,
                title=f"CRITICAL: '{etc_crontab}' is Writable!",
                description=f"The main system crontab file '{etc_crontab}' is writable by the current user.",
                recommendation="This allows direct modification of system-wide cron jobs. You can inject commands to be executed as root by modifying this file."
            )

    # Check common cron script directories for writable scripts
    common_cron_script_dirs = ['/etc/cron.hourly', '/etc/cron.daily', '/etc/cron.weekly', '/etc/cron.monthly']
    for cron_dir in common_cron_script_dirs:
        if os.path.isdir(cron_dir):
            try:
                for script_name in os.listdir(cron_dir):
                    script_path = os.path.join(cron_dir, script_name)
                    if os.path.isfile(script_path) and is_writable_by_current_user(script_path):
                        findings_collector.add_finding(
                            check_type="Cron Job Misconfiguration",
                            severity=Severity.HIGH,
                            title=f"Writable Script in System Cron Directory: '{script_path}'",
                            description=f"A script in a system cron directory ('{cron_dir}') is writable by the current user.",
                            recommendation="If this script is executed by a root-owned cron job, you can modify its content to execute arbitrary commands as root."
                        )
            except PermissionError:
                print(f"  [!] Permission denied when accessing '{cron_dir}'. Skipping script checks in this directory.")
            except Exception as e:
                print(f"  [!] Error checking '{cron_dir}': {e}")

    print("-" * 40)


def check_nfs_shares():
    """
    Checks for NFS shares mounted with 'no_root_squash'.
    """
    print("[*] Checking for NFS shares with 'no_root_squash' (client side)...")
    
    mount_output = run_command(['cat', '/proc/mounts'], suppress_errors=True)
    if not mount_output:
        findings_collector.add_finding(
            check_type="NFS Shares",
            severity=Severity.LOW,
            title="Could Not Read /proc/mounts",
            description="Unable to read /proc/mounts to check for NFS shares.",
            recommendation="Verify that /proc/mounts is readable by the current user."
        )
        print("-" * 40)
        return

    found_nfs_issue = False
    for line in mount_output.splitlines():
        if " nfs " in line or " nfs4 " in line:
            parts = line.split()
            if len(parts) > 3:
                mount_options = parts[3]
                if "no_root_squash" in mount_options:
                    findings_collector.add_finding(
                        check_type="NFS Shares",
                        severity=Severity.HIGH,
                        title="NFS Share Mounted with 'no_root_squash'",
                        description=f"NFS share '{parts[0]}' mounted on '{parts[1]}' has the 'no_root_squash' option enabled.",
                        recommendation="This is a high-risk misconfiguration. If you can gain root access on this client machine, you can access the NFS share with root privileges on the remote server. Create an SUID binary on the share as root client, then execute it on the share from the server."
                    )
                    found_nfs_issue = True
    
    if not found_nfs_issue:
        print("  [-] No NFS shares found mounted with 'no_root_squash' on this client.")
    print("-" * 40)


def check_misconfigured_services():
    """
    Checks for potentially misconfigured systemd units or other services
    that could be exploited due to writable files.
    """
    print("[*] Checking for misconfigured services (basic check)...")
    found_issues = False

    systemd_paths = [
        "/etc/systemd/system/",
        "/lib/systemd/system/"
    ]

    for sysd_path in systemd_paths:
        if os.path.isdir(sysd_path):
            try:
                for root, dirs, files in os.walk(sysd_path):
                    for name in files:
                        if name.endswith(".service") or name.endswith(".timer") or name.endswith(".socket"):
                            filepath = os.path.join(root, name)
                            if is_writable_by_current_user(filepath):
                                findings_collector.add_finding(
                                    check_type="Misconfigured Service",
                                    severity=Severity.HIGH,
                                    title=f"Writable Systemd Unit File: '{filepath}'",
                                    description=f"A systemd unit file ('{filepath}') is writable by the current user.",
                                    recommendation="If this service runs as root, modifying its definition (e.g., adding an ExecStartPre/Post command) can lead to arbitrary code execution as root."
                                )
                                found_issues = True
            except PermissionError:
                print(f"  [!] Permission denied when accessing '{sysd_path}'. Skipping systemd unit checks here.")
            except Exception as e:
                print(f"  [!] Error checking '{sysd_path}': {e}")
    
    init_d_path = "/etc/init.d"
    if os.path.isdir(init_d_path):
        try:
            for filename in os.listdir(init_d_path):
                filepath = os.path.join(init_d_path, filename)
                if os.path.isfile(filepath) and is_writable_by_current_user(filepath):
                    findings_collector.add_finding(
                        check_type="Misconfigured Service",
                        severity=Severity.HIGH,
                        title=f"Writable Init.d Script: '{filepath}'",
                        description=f"An init.d script ('{filepath}') is writable by the current user.",
                        recommendation="If this script runs as root during boot or service restart, you can modify it to execute arbitrary commands as root."
                    )
                    found_issues = True
        except PermissionError:
            print(f"  [!] Permission denied when accessing '{init_d_path}'. Skipping init.d script checks here.")
        except Exception as e:
            print(f"  [!] Error checking '{init_d_path}': {e}")


    findings_collector.add_finding(
        check_type="Misconfigured Service",
        severity=Severity.INFO,
        title="Manual Check for Exposed Service Credentials",
        description="Recommend manually checking for exposed credentials in service configuration files (e.g., database configs).",
        recommendation="Common locations: /etc/, /var/www/, /opt/, application-specific directories. Look for passwords, API keys, or sensitive paths."
    )
    
    print("-" * 40)

def check_linux_capabilities():
    """
    Checks for files with special Linux capabilities.
    """
    print("[*] Checking for Linux capabilities...")
    found_capabilities = False
    
    getcap_path = run_command(['which', 'getcap'], suppress_errors=True)
    if not getcap_path:
        findings_collector.add_finding(
            check_type="Linux Capabilities",
            severity=Severity.LOW,
            title="'getcap' Command Not Found",
            description="The 'getcap' command is not found. Cannot check for Linux capabilities.",
            recommendation="Consider installing 'libcap2-bin' (Debian/Ubuntu) or 'libcap' (CentOS/RHEL) to enable this check."
        )
        print("-" * 40)
        return

    paths_to_check = ['/usr/bin', '/bin', '/usr/sbin', '/sbin']
    all_caps_output = ""

    for path in paths_to_check:
        if os.path.isdir(path):
            try:
                cmd = ['sudo', getcap_path, '-r', path]
                output = run_command(cmd, suppress_errors=True) # Suppress errors for sudo's permission denied messages
                all_caps_output += output + "\n"
            except Exception as e:
                print(f"  [!] Error running getcap on {path}: {e}") # Specific error for getcap failures


    if all_caps_output:
        lines = all_caps_output.splitlines()
        for line in lines:
            # Filter out empty lines or lines that just indicate "no capabilities"
            if line and "Cap" in line and "no capabilities" not in line:
                # Basic parsing to extract path and caps
                parts = line.split(" = ")
                filepath = parts[0].strip()
                caps = parts[1].strip() if len(parts) > 1 else ""

                findings_collector.add_finding(
                    check_type="Linux Capabilities",
                    severity=Severity.HIGH, # Capabilities are often high impact
                    title=f"File with Linux Capabilities: '{os.path.basename(filepath)}'",
                    description=f"The file '{filepath}' has special Linux capabilities assigned.",
                    details=f"Capabilities: {caps}",
                    recommendation=f"Research this file '{filepath}' and its assigned capabilities on resources like GTFOBins or general Linux capability exploitation guides. For example, CAP_NET_RAW allows raw packet manipulation, CAP_SETUID allows changing user ID."
                )
                found_capabilities = True
    
    if not found_capabilities:
        print("  [-] No significant Linux capabilities found on commonly checked binaries.")
    print("-" * 40)


def check_weak_log_file_permissions():
    """
    Checks for weak permissions on common system log files.
    """
    print("[*] Checking for weak permissions on log files...")
    
    common_log_dirs = [
        "/var/log",
        "/var/log/apache2",
        "/var/log/nginx",
        "/var/log/mysql",
        "/var/log/syslog",
        "/var/log/auth.log",
        "/var/log/kern.log"
    ]
    
    specific_log_files = [
        "/var/log/auth.log",
        "/var/log/syslog",
        "/var/log/messages",
        "/var/log/kern.log",
        "/var/log/lastlog",
        "/var/log/wtmp",
        "/var/log/btmp",
        "/var/log/faillog"
    ]

    checked_files = set()

    for log_path in common_log_dirs + specific_log_files: # Combine to handle both
        if os.path.exists(log_path) and log_path not in checked_files:
            if os.path.isdir(log_path):
                try:
                    for root, dirs, files in os.walk(log_path):
                        for name in files:
                            filepath = os.path.join(root, name)
                            if filepath in checked_files:
                                continue
                            checked_files.add(filepath)

                            if is_readable_by_others(filepath):
                                if is_writable_by_current_user(filepath):
                                    findings_collector.add_finding(
                                        check_type="Weak Log File Permissions",
                                        severity=Severity.CRITICAL,
                                        title=f"CRITICAL: Writable Log File by Current User: '{filepath}'",
                                        description=f"The log file '{filepath}' is writable by the current user (Mode: {oct(os.stat(filepath).st_mode)[-4:]}).",
                                        recommendation="This is a critical flaw allowing log tampering, deletion to hide tracks, or potentially injection if a privileged service parses these logs."
                                    )
                                else:
                                    findings_collector.add_finding(
                                        check_type="Weak Log File Permissions",
                                        severity=Severity.MEDIUM,
                                        title=f"Log File Readable by Others: '{filepath}'",
                                        description=f"The log file '{filepath}' is readable by other users (Mode: {oct(os.stat(filepath).st_mode)[-4:]}).",
                                        recommendation="Review its content for sensitive information (e.g., credentials, internal IPs, errors, software versions) that could aid further reconnaissance or escalation."
                                    )
                except PermissionError:
                    print(f"  [!] Permission denied when accessing log directory '{log_path}'. Skipping files in this directory.")
                except Exception as e:
                    print(f"  [!] Error checking log directory '{log_path}': {e}")
            elif os.path.isfile(log_path): # Handle individual files from the specific_log_files list
                if is_readable_by_others(log_path):
                    if is_writable_by_current_user(log_path):
                        findings_collector.add_finding(
                            check_type="Weak Log File Permissions",
                            severity=Severity.CRITICAL,
                            title=f"CRITICAL: Writable Log File by Current User: '{log_path}'",
                            description=f"The log file '{log_path}' is writable by the current user (Mode: {oct(os.stat(log_path).st_mode)[-4:]}).",
                            recommendation="This is a critical flaw allowing log tampering, deletion to hide tracks, or potentially injection if a privileged service parses these logs."
                        )
                    else:
                        findings_collector.add_finding(
                            check_type="Weak Log File Permissions",
                            severity=Severity.MEDIUM,
                            title=f"Log File Readable by Others: '{log_path}'",
                            description=f"The log file '{log_path}' is readable by other users (Mode: {oct(os.stat(log_path).st_mode)[-4:]}).",
                            recommendation="Review its content for sensitive information (e.g., credentials, internal IPs, errors, software versions) that could aid further reconnaissance or escalation."
                        )
        
    print("-" * 40)


def check_installed_software_enumeration():
    """
    Performs a basic enumeration of commonly installed software and suggests
    checking for known vulnerabilities. This is mostly informational.
    """
    print("[*] Performing basic installed software enumeration...")
    
    software_indicators = {
        "Apache HTTP Server": ["/etc/apache2/", "/usr/sbin/apache2", "httpd"],
        "Nginx Web Server": ["/etc/nginx/", "/usr/sbin/nginx", "nginx"],
        "MySQL/MariaDB": ["/etc/mysql/", "/usr/bin/mysql", "mysqld"],
        "PostgreSQL": ["/etc/postgresql/", "/usr/bin/psql", "postgres"],
        "Docker": ["/usr/bin/docker", "/var/run/docker.sock"],
        "Kubernetes (kubectl)": ["/usr/bin/kubectl"],
        "OpenSSH Server": ["/etc/ssh/sshd_config"],
        "Samba": ["/etc/samba/", "/usr/sbin/smbd"],
        "Bind DNS (named)": ["/etc/bind/", "/usr/sbin/named"],
        "Redis": ["/etc/redis/", "/usr/bin/redis-server"],
        "Squid Proxy": ["/etc/squid/", "/usr/sbin/squid"],
        "Tomcat": ["/var/lib/tomcat", "/usr/share/tomcat", "tomcat"],
        "PHP": ["/usr/bin/php", "php-fpm"]
    }

    running_processes_output = run_command(['ps', 'aux'], suppress_errors=True)
    
    for software, indicators in software_indicators.items():
        is_found = False
        for indicator in indicators:
            if os.path.exists(indicator):
                findings_collector.add_finding(
                    check_type="Software Enumeration",
                    severity=Severity.INFO,
                    title=f"Detected Software: {software}",
                    description=f"Indication found via path: {indicator}.",
                    recommendation=f"Research known vulnerabilities (CVEs, Exploit-DB) for '{software}' specific to its version. Look for default credentials, common misconfigurations, or unpatched flaws. Use tools like `searchsploit`."
                )
                is_found = True
                break # Only need one indicator to find
            if running_processes_output and indicator in running_processes_output:
                findings_collector.add_finding(
                    check_type="Software Enumeration",
                    severity=Severity.INFO,
                    title=f"Detected Software: {software}",
                    description=f"Indication found via running process: '{indicator}'.",
                    recommendation=f"Research known vulnerabilities (CVEs, Exploit-DB) for '{software}' specific to its version. Look for default credentials, common misconfigurations, or unpatched flaws. Use tools like `searchsploit`."
                )
                is_found = True
                break
        
    print("-" * 40)


def run_all_advanced_checks():
    """Runs all advanced privilege escalation checks."""
    print("\n" + "=" * 50)
    print("  Running Advanced Privilege Escalation Checks  ")
    print("=" * 50 + "\n")

    check_environment_variables()
    check_cron_job_misconfigurations()
    check_nfs_shares()
    check_misconfigured_services()
    check_linux_capabilities()
    check_weak_log_file_permissions()
    check_installed_software_enumeration()

# Optional: Test the module independently
if __name__ == "__main__":
    run_all_advanced_checks()