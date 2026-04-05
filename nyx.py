"""
PROJECT NYX: Primordial Log Intelligence
Filename: main.py
Version: 1.0
Description: The central "Glue" that holds the project together. This is the 
primary entry point that controls the flow of the program, validates 
environment permissions, and benchmarks performance.
"""

import analyze
import config
import sys
import os
from datetime import datetime
import report_generator
import subprocess
import time


RED = "\033[91m"
GREEN = "\033[92m"
BLUE = "\033[94m"
RESET = "\033[0m"

def show_help():
    print("="*80)
    print(f"                {GREEN}NYX: Primordial Log Forensics & Attribution{RESET}             ")
    print("="*80)
    print(f"{BLUE}USAGE:{RESET} python3 nyx.py <file_path> <type>")
    
    print(f"\n{BLUE}ENGINE MODES:{RESET}")
    print("  auth           Optimized for SSH, Sudo, and PAM authentication logs")
    print("  access         Web server traffic analysis (Coming Soon)")
    
    print(f"\n{BLUE}PERSONALIZATION (config.py):{RESET}")
    print("  [+] Thresholds : Adjust 'THRESHOLD' and 'TOTAL_VOLUME_THRESHOLD' for sensitivity")
    print("  [+] Whitelist  : Add trusted IPs to 'WHITELIST' to filter internal noise")
    print("  [+] Targets    : Define 'CRITICAL_USERS' to prioritize high-value accounts")
    
    print(f"\n{BLUE}EXAMPLES:{RESET}")
    print("  sudo python3 nyx.py /var/log/auth.log auth")
    print("="*80)

def get_line_count(filename):
    """
    Utilizes the system-level 'wc' utility for rapid line counting.
    This is much faster than reading a 500k+ line file directly in Python.
    """
    output = subprocess.check_output(['wc', '-l', filename])
    return int(output.split()[0])

def main():
    if len(sys.argv) < 2:
        print(f"{RED}[-] Error: No arguments provided.{RESET}")
        print(f"[*] Use 'python3 {sys.argv[0]} --help' to see correct syntax.")
        sys.exit(1)

    if any(arg in ["-h", "--help"] for arg in sys.argv):
        show_help()
        sys.exit(0)

    if len(sys.argv) != 3:
        print(f"{RED}[-] Error: Incorrect Syntax.{RESET}")
        print(f"[*] Expected: python3 {sys.argv[0]} <file_path> <log_type>")
        print(f"[*] Example:  python3 {sys.argv[0]} /var/log/auth.log auth")
        sys.exit(1)

    log_path = sys.argv[1]
    log_type = sys.argv[2].lower()

    if not os.path.exists(log_path):
        print(f"{RED}[-] ERROR: File '{log_path}' not found.{RESET}")
        sys.exit(1)

    if not os.access(log_path, os.R_OK):
        print("="*80)
        print(f"{RED}[-] ERROR: Permission Denied for '{log_path}'{RESET}")
        print("[*] Accessing system logs usually requires root privileges.")
        print(f"{BLUE}[*] TRY: sudo python3 main.py {log_path} {log_type}{RESET}")
        print("="*80)
        sys.exit(1)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_name = os.path.basename(log_path) 
    report_filename = f"report_{log_name}_{timestamp}.txt"

    reports_dir = os.path.join(os.path.dirname(__file__), "reports")
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)

    report_path = os.path.join(reports_dir, report_filename)
    print(f"[*] Starting Forensic Analysis on: {BLUE}{os.path.abspath(log_path)}{RESET}")

    start_bench = time.time()

    try:
        if log_type == "auth":
            config.AUTH_LOG_FILE_PATH = log_path 
            line_count = get_line_count(config.AUTH_LOG_FILE_PATH)
            
            result, ips = analyze.analyze_auth_file(log_path)
            
            end_bench = time.time()
            total_execution_time = end_bench - start_bench
            
            report_generator.generate_report(report_path, ips, result, line_count, total_execution_time, log_path)
            
            print(f"{GREEN}[+] Analysis Complete in {total_execution_time:.2f}s.{RESET}")
            print(f"[*] Results saved to: {RED}reports/{report_filename}{RESET}")

        elif log_type == "access":
            print(f"{RED}[-] Error: 'access' log analysis is not yet implemented.{RESET}")
            print("[*] Planned for a future update.")
            
        elif log_type == "sys":
            print(f"{RED}[-] Error: 'sys' log analysis is not yet implemented.{RESET}")
            print("[*] Planned for a future update.")
            
        else:
            print(f"{RED}[-] Error: '{log_type}' is not a supported log type.{RESET}")
            print(f"[*] Supported types: {GREEN}auth{RESET}")
    
    except Exception as e:
        print(f"{RED}[!] An unexpected fatal error occurred: {e}{RESET}")
        sys.exit(1)

if __name__ == "__main__":
    main()