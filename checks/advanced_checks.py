# checks/advanced_checks.py

import os
import subprocess
import stat # For checking file modes and permissions

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
            # For debugging, you might want to print e.stderr as well
            # print(f"  [!] Error running command '{' '.join(command)}': {e.stderr.strip()}")
            pass # Suppress most errors here for cleaner output, let individual checks handle specific messages
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
            return bool(mode & stat.S_IROTH) # S_IROTH checks for world-readable bit
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
        print(f"  [+] Current PATH: {path_env}")
        path_dirs = path_env.split(':')
        for p_dir in path_dirs:
            if os.path.isdir(p_dir) and is_writable_by_current_user(p_dir):
                print(f"      [!] WARNING: PATH directory '{p_dir}' is writable by current user.")
                print("          This could allow injection of malicious executables (e.g., fake 'ls').")
        
    ld_preload_env = os.getenv('LD_PRELOAD')
    if ld_preload_env:
        print(f"  [+] LD_PRELOAD is set: {ld_preload_env}")
        print("      This could be legitimate, but check if it points to a malicious or vulnerable library.")
    else:
        print("  [-] LD_PRELOAD is not set (Good).")

    suspicious_envs = ['LD_LIBRARY_PATH', 'IFS', 'PS1', 'BASH_ENV']
    for env_var in suspicious_envs:
        val = os.getenv(env_var)
        if val:
            print(f"  [+] Environment variable '{env_var}' is set: {val}")
            print(f"      Consider if '{env_var}' can be manipulated for exploit.")
    
    print("-" * 40)


def check_cron_job_misconfigurations():
    """
    Checks for cron jobs that are potentially exploitable due to weak permissions
    on scripts they execute or the cron directories themselves.
    """
    print("[*] Checking for cron job misconfigurations...")
    found_issues = False

    cron_d_path = "/etc/cron.d"
    if os.path.isdir(cron_d_path):
        for filename in os.listdir(cron_d_path):
            filepath = os.path.join(cron_d_path, filename)
            if os.path.isfile(filepath) and is_writable_by_current_user(filepath):
                print(f"  [+] WARNING: Writable cron file in '{cron_d_path}': '{filepath}'")
                print("      A low-privileged user could modify this cron job, potentially leading to root execution.")
                found_issues = True

    crontabs_path = "/var/spool/cron/crontabs"
    if os.path.isdir(crontabs_path):
        for username_file in os.listdir(crontabs_path):
            filepath = os.path.join(crontabs_path, username_file)
            if os.path.isfile(filepath) and is_writable_by_current_user(filepath):
                print(f"  [+] NOTE: User crontab file writable: '{filepath}'")
                print("      This means the user could modify their own cron jobs, which is normal. But check if it belongs to an 'admin' user.")

    etc_crontab = "/etc/crontab"
    if os.path.exists(etc_crontab) and is_writable_by_current_user(etc_crontab):
        print(f"  [+] CRITICAL: '{etc_crontab}' is writable by the current user!")
        print("      This would allow direct modification of system-wide cron jobs, likely leading to root access.")
        found_issues = True

    common_cron_script_dirs = ['/etc/cron.hourly', '/etc/cron.daily', '/etc/cron.weekly', '/etc/cron.monthly']
    for cron_dir in common_cron_script_dirs:
        if os.path.isdir(cron_dir):
            for script_name in os.listdir(cron_dir):
                script_path = os.path.join(cron_dir, script_name)
                if os.path.isfile(script_path) and is_writable_by_current_user(script_path):
                    print(f"  [+] WARNING: Writable script in cron directory: '{script_path}'")
                    print("      If this script is run by root's cron, a low-privileged user could modify it.")
                    found_issues = True

    if not found_issues:
        print("  [-] No obvious cron job misconfigurations found based on writable files.")
    print("-" * 40)


def check_nfs_shares():
    """
    Checks for NFS shares mounted with 'no_root_squash'.
    """
    print("[*] Checking for NFS shares with 'no_root_squash' (client side)...")
    found_nfs_issues = False
    
    mount_output = run_command(['cat', '/proc/mounts'], suppress_errors=True)
    if not mount_output:
        print("  [!] Could not read /proc/mounts to check NFS shares.")
        print("      Make sure /proc/mounts is readable.")
        print("-" * 40)
        return

    for line in mount_output.splitlines():
        if " nfs " in line or " nfs4 " in line:
            parts = line.split()
            if len(parts) > 3:
                mount_options = parts[3]
                if "no_root_squash" in mount_options:
                    print(f"  [+] WARNING: NFS share '{parts[0]}' mounted on '{parts[1]}' with 'no_root_squash' option!")
                    print("      This is a high-risk misconfiguration. A root user on the client can act as root on the server for this share.")
                    print("      This typically requires control over the NFS client machine to exploit.")
                    found_nfs_issues = True

    if not found_nfs_issues:
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
            for root, dirs, files in os.walk(sysd_path):
                for name in files:
                    if name.endswith(".service") or name.endswith(".timer") or name.endswith(".socket"):
                        filepath = os.path.join(root, name)
                        if is_writable_by_current_user(filepath):
                            print(f"  [+] WARNING: Writable systemd unit file found: '{filepath}'")
                            print("      If this service runs as root, a low-privileged user could modify its definition.")
                            found_issues = True
    
    init_d_path = "/etc/init.d"
    if os.path.isdir(init_d_path):
        for filename in os.listdir(init_d_path):
            filepath = os.path.join(init_d_path, filename)
            if os.path.isfile(filepath) and is_writable_by_current_user(filepath):
                print(f"  [+] WARNING: Writable init.d script found: '{filepath}'")
                print("      If this script runs as root, a low-privileged user could modify it.")
                found_issues = True

    print("  [.] NOTE: Manually check for exposed credentials in service configuration files (e.g., database configs).")
    print("      Common locations: /etc/, /var/www/, /opt/, application-specific directories.")
    
    if not found_issues:
        print("  [-] No easily identifiable misconfigured service unit/script files found.")
    print("-" * 40)

def check_linux_capabilities():
    """
    Checks for files with special Linux capabilities.
    """
    print("[*] Checking for Linux capabilities...")
    found_capabilities = False
    
    # -r: recursive search
    # -v: verbose output
    # 2>/dev/null: suppress stderr for permission denied errors
    # Note: 'getcap' might not be installed by default on all distros (e.g., part of libcap2-bin)
    
    # We'll run it on common binary paths and also a recursive /usr/bin if getcap exists
    paths_to_check = ['/usr/bin', '/bin', '/usr/sbin', '/sbin']
    
    # Check if getcap command exists
    getcap_path = run_command(['which', 'getcap'], suppress_errors=True)
    if not getcap_path:
        print("  [!] 'getcap' command not found. Cannot check for Linux capabilities.")
        print("      Consider installing 'libcap2-bin' (Debian/Ubuntu) or 'libcap' (CentOS/RHEL).")
        print("-" * 40)
        return

    all_caps_output = ""
    for path in paths_to_check:
        if os.path.isdir(path):
            # Limiting to top-level for performance, a full '/' scan can be very long
            # For a more thorough scan, one could use `getcap -r / 2>/dev/null` if patience allows.
            cmd = ['sudo', getcap_path, '-r', path] # Use sudo if getcap requires it to read all files
            output = run_command(cmd, suppress_errors=True)
            all_caps_output += output + "\n"

    # Also try a broader, less restrictive search if possible (might require root, but useful if the tool is run as root for a full audit later)
    # If the user is running as non-root, 'sudo getcap -r /' will likely fail for many files.
    # The initial checks above are more realistic for a non-root user.
    # If a non-root user can run `getcap -r /path`, it's an interesting finding itself.
    
    if all_caps_output:
        lines = all_caps_output.splitlines()
        for line in lines:
            if line and "Cap" in line: # Basic check for lines indicating capabilities
                print(f"  [+] Found file with capabilities: {line.strip()}")
                print("      ACTION: Research this file. Misconfigured capabilities (e.g., CAP_NET_RAW, CAP_SETUID) can be exploited.")
                found_capabilities = True
    
    if not found_capabilities:
        print("  [-] No significant Linux capabilities found on commonly checked binaries.")
    print("-" * 40)


def check_weak_log_file_permissions():
    """
    Checks for weak permissions on common system log files.
    """
    print("[*] Checking for weak permissions on log files...")
    found_weak_logs = False
    
    common_log_dirs = [
        "/var/log",
        "/var/log/apache2", # For Apache
        "/var/log/nginx",   # For Nginx
        "/var/log/mysql",   # For MySQL
        "/var/log/syslog", # Specific file on some systems
        "/var/log/auth.log", # Specific file on some systems
        "/var/log/kern.log"
    ]
    
    # Files to check specifically, even if in common dirs
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

    checked_files = set() # To avoid duplicate checks

    for log_path in common_log_dirs:
        if os.path.isdir(log_path):
            # Walk through the directory to find all files
            for root, dirs, files in os.walk(log_path):
                for name in files:
                    filepath = os.path.join(root, name)
                    if filepath in checked_files:
                        continue
                    checked_files.add(filepath)

                    if is_readable_by_others(filepath):
                        # Some log files like lastlog, wtmp are often readable by others for auditing.
                        # We'll flag writable ones as critical.
                        if is_writable_by_current_user(filepath):
                            print(f"  [+] CRITICAL: Writable log file by current user: '{filepath}' (Mode: {oct(os.stat(filepath).st_mode)[-4:]})")
                            print("      This could allow log tampering or deletion to hide tracks, or injection if logs are parsed by privileged services.")
                            found_weak_logs = True
                        else:
                            print(f"  [+] NOTE: Log file readable by others: '{filepath}' (Mode: {oct(os.stat(filepath).st_mode)[-4:]})")
                            print("      Review its content for sensitive information (e.g., usernames, IPs, errors) that could aid escalation.")
                            found_weak_logs = True
        elif os.path.isfile(log_path) and log_path not in checked_files: # For specific_log_files listed as full paths
            checked_files.add(log_path)
            if is_readable_by_others(log_path):
                if is_writable_by_current_user(log_path):
                    print(f"  [+] CRITICAL: Writable log file by current user: '{log_path}' (Mode: {oct(os.stat(log_path).st_mode)[-4:]})")
                    found_weak_logs = True
                else:
                    print(f"  [+] NOTE: Log file readable by others: '{log_path}' (Mode: {oct(os.stat(log_path).st_mode)[-4:]})")
                    found_weak_logs = True


    if not found_weak_logs:
        print("  [-] No obvious weak permissions found on common log files.")
    print("-" * 40)


def check_installed_software_enumeration():
    """
    Performs a basic enumeration of commonly installed software and suggests
    checking for known vulnerabilities. This is mostly informational.
    """
    print("[*] Performing basic installed software enumeration...")
    
    # List of common software to check for via path presence or known processes
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
        "Tomcat": ["/var/lib/tomcat", "/usr/share/tomcat"], # Common install paths
        "PHP": ["/usr/bin/php", "php-fpm"]
    }

    found_software = []
    
    # Check for paths and running processes
    running_processes_output = run_command(['ps', 'aux'], suppress_errors=True)

    for software, indicators in software_indicators.items():
        is_found = False
        for indicator in indicators:
            if os.path.exists(indicator):
                if os.path.isdir(indicator):
                    found_software.append(f"      [+] Directory exists: {software} ({indicator})")
                    is_found = True
                    break
                elif os.path.isfile(indicator):
                    found_software.append(f"      [+] File exists: {software} ({indicator})")
                    is_found = True
                    break
            if running_processes_output and indicator in running_processes_output:
                found_software.append(f"      [+] Process running: {software} (indicated by '{indicator}')")
                is_found = True
                break
        
    if found_software:
        print("  [+] Detected potentially installed software/services:")
        for item in found_software:
            print(item)
        print("      ACTION: For each detected software, research known vulnerabilities (CVEs, Exploit-DB) specific to its version.")
        print("      Check for default credentials, misconfigurations, or unpatched flaws.")
    else:
        print("  [-] No common server software/services detected via basic checks.")
    print("-" * 40)


def run_all_advanced_checks():
    """Runs all advanced privilege escalation checks."""
    print("\n" + "=" * 50)
    print("  Running More Advanced Privilege Escalation Checks  ")
    print("=" * 50 + "\n")

    check_environment_variables()
    check_cron_job_misconfigurations()
    check_nfs_shares()
    check_misconfigured_services()
    check_linux_capabilities()        # New Advanced Check 1
    check_weak_log_file_permissions() # New Advanced Check 2
    check_installed_software_enumeration() # New Advanced Check 3

# Optional: Test the module independently
if __name__ == "__main__":
    run_all_advanced_checks()