"""
PROJECT NYX: Primordial Log Intelligence
Filename: analyze.py
Version: 1.0
Description: The "Brain" of the tool. Handles stateful PID tracking, 
burst-window detection, and IP-based attribution.
"""
import parser
import config
import report_generator
from datetime import datetime
import gzip
tracker = {}

def analyze_auth_file(auth_file):
    results = {}
    report_ips = []
    alerts_id = 1
    current_year = datetime.now().year 
    open_func = gzip.open if auth_file.endswith('.gz') else open
    mode = 'rt' if auth_file.endswith('.gz') else 'r'
    

    with open_func(auth_file, mode, encoding="utf-8") as file:
        for line in file:
            data = parser.auth_line_cleaner(line, tracker)

            if data:
                ip = data.get("ip")
                increment = data.get("count", 1)

                if not ip and "id" in data:
                    ip = tracker.get(data["id"])
                
                if ip:
                    log_time = datetime.strptime(f"{current_year} {data['time']}", "%Y %b %d %H:%M:%S")
                    user = data.get('user')
                    is_success = "Accepted" in line
                    if ip not in report_ips:
                        report_ips.append(ip)

                    if ip not in results:
                        results[ip] = {
                            "first_seen": log_time,
                            "last_seen": log_time,
                            "total_strikes": increment,
                            "total_users": {user} if user else set(),
                            "burst_buffer": {
                                "anchor_time": log_time,
                                "latest_hit": log_time,
                                "strikes": increment,
                                "users_in_burst": {user} if user else set(),
                                "breach_detected": is_success,
                                "evidence_sample": [line.strip()] 
                            },
                            "volume_evidence" : [line.strip()],
                            "alerts": {}
                        }
                    else:
                        results[ip]["total_strikes"] += increment
                        results[ip]["last_seen"] = log_time
                        if user:
                            results[ip]["total_users"].add(user)
                        if len(results[ip]["volume_evidence"]) < 4:
                            results[ip]["volume_evidence"].append(line.strip())
                        time_gap = (log_time - results[ip]["burst_buffer"]["latest_hit"]).total_seconds()
                        
                        #january bug fix
                        if time_gap < 0:
                            time_gap += 31536000
                        if time_gap < config.MAX_BURST_GAP:
                            results[ip]["burst_buffer"]["latest_hit"] = log_time
                            results[ip]["burst_buffer"]["strikes"] += increment
                            if user:
                                results[ip]["burst_buffer"]["users_in_burst"].add(user)
                            if is_success:
                                results[ip]["burst_buffer"]["breach_detected"] = True

                            if len(results[ip]["burst_buffer"]["evidence_sample"]) < 6:
                                results[ip]["burst_buffer"]["evidence_sample"].append(line.strip())
                        else:
                            buffer = results[ip]["burst_buffer"]
                            if buffer["strikes"] >= config.THRESHOLD:
                                if ip in config.WHITELIST:
                                    status = "WHITELIST IP ACTIVITY : BURST"
                                elif buffer["breach_detected"]:
                                    status = "CRITICAL : BREACH DETECTED"
                                else:
                                    status = "SUSPICIOUS ACTIVITY : BURST"

                                results[ip]["alerts"][alerts_id] = {
                                    "status": status,
                                    "start_time": buffer["anchor_time"],
                                    "last_time": buffer["latest_hit"],
                                    "strikes_at_detection": buffer["strikes"],
                                    "target_users": list(buffer["users_in_burst"]),
                                    "event_duration": buffer["latest_hit"] - buffer["anchor_time"],
                                    "evidence_sample": buffer["evidence_sample"]
                                }
                                alerts_id += 1
                            
                            results[ip]["burst_buffer"] = {
                                "anchor_time": log_time,
                                "latest_hit": log_time,
                                "strikes": increment,
                                "users_in_burst": {user} if user else set(),
                                "breach_detected" : is_success,
                                "evidence_sample": [line.strip()]
                            }

    # Final sweep of active buffers
    for ip, ip_data in results.items():
        buffer = ip_data["burst_buffer"]
        if buffer["strikes"] >= config.THRESHOLD:
            if ip in config.WHITELIST:
                status = "WHITELIST IP ACTIVITY"
            elif buffer["breach_detected"]:
                status = "CRITICAL : BREACH DETECTED"
            else:
                status = "SUSPICIOUS ACTIVITY : BURST"

            ip_data["alerts"][alerts_id] = {
                "status": status,
                "start_time": buffer["anchor_time"],
                "last_time": buffer["latest_hit"],
                "strikes_at_detection": buffer["strikes"],
                "target_users": list(buffer["users_in_burst"]),
                "event_duration": buffer["latest_hit"] - buffer["anchor_time"],
                "evidence_sample": buffer["evidence_sample"]
            }
            alerts_id += 1

        total_duration = (ip_data["last_seen"] - ip_data["first_seen"]).total_seconds()
        if ip_data["total_strikes"] > config.TOTAL_VOLUME_THRESHOLD and total_duration < config.VOLUME_WINDOW:
            if ip in config.WHITELIST:
                status = "WHITELIST IP ACTIVITY : HIGH VOLUME"
            else:
                status = "SUSPICIOUS ACTIVITY : HIGH VOLUME"

            ip_data["alerts"][alerts_id] = {
                "status": status,
                "start_time": ip_data["first_seen"],
                "last_time": ip_data["last_seen"],
                "strikes_at_detection": ip_data["total_strikes"],
                "target_users": list(ip_data["total_users"]), 
                "event_duration": ip_data["last_seen"] - ip_data["first_seen"],
                "evidence_sample": ip_data["volume_evidence"]
            }
            alerts_id += 1

    return results, report_ips

def analyze_sys_file():
    pass

def analyze_access_file():
    pass