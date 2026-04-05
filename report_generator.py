"""
PROJECT NYX: Primordial Log Intelligence
Filename: report_generator.py
Version: 1.0
Description: The "Writer." Transforms structured analysis results 
into a human-readable forensic security report.
"""

from datetime import datetime
import config

def generate_report(file_name, ips, results, line_count, execution_time, target_log):
    with open(file_name, "w") as file:
        # --- HEADER ---
        file.write("="*73 + "\n")
        file.write(" " * 20 + "NYX: DETAILED SECURITY INCIDENT REPORT\n")
        file.write("="*73 + "\n")
        file.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
        file.write(f"Target Log: {target_log}\n")
        file.write(f"Status:    ANALYSIS COMPLETE\n")
        file.write("-" * 73 + "\n\n")

        # --- [1] SUMMARY ---
        file.write("[1] SUMMARY OF ACTIVITY\n")
        file.write("-" * 24 + "\n")
        file.write(f"Total lines processed : {line_count}\n")
        file.write(f"Analysis Duration     : {execution_time:.4f} seconds\n")
        file.write(f"Unique IPs Scanned    : {len(ips)}\n")
        
        flagged_ips = [ip for ip, data in results.items() if data.get("alerts")]
        total_alerts = sum(len(data.get("alerts", {})) for ip, data in results.items())
        file.write(f"Flagged Incidents     : {total_alerts}\n")
        file.write(f"Flagged IP Addresses  : {', '.join(flagged_ips) if flagged_ips else 'NONE'}\n\n")

        # --- [2] INCIDENT DETAILS ---
        file.write("[2] INCIDENT DETAILS\n")
        file.write("-" * 20 + "\n")
        
        alert_counter = 1
        for ip in flagged_ips:
            ip_alerts = results[ip]["alerts"]
            for a_id, details in ip_alerts.items():
                file.write("-" * 73 + "\n")
                file.write(f"ID : {alert_counter} | IP : {ip} | STATUS : {details['status']}\n")
                file.write("-" * 73 + "\n")

                # Extraction and Formatting
                target_users = ", ".join(sorted(details.get("target_users", ["N/A"])))
                first_seen = details["start_time"].strftime("%m-%d %H:%M:%S")
                last_seen = details["last_time"].strftime("%m-%d %H:%M:%S")
                duration = details.get("event_duration", "N/A")

                file.write(f" > Target Accounts      : {target_users}\n")
                file.write(f" > Strikes at Detection : {details['strikes_at_detection']}\n")
                file.write(f" > Event Duration       : {duration}\n")
                file.write(f" > Window Start         : {first_seen}\n")
                file.write(f" > Window End           : {last_seen}\n")
                
                file.write(" > Evidence Sample      :\n")
                for raw_line in details.get("evidence_sample", []):
                    file.write(f"   RAW: {raw_line.strip()}\n")
                
                file.write("\n")
                alert_counter += 1

        file.write("=" * 73 + "\n")
        file.write("[END OF REPORT]\n")
        file.write("=" * 73 + "\n")