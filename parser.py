"""
PROJECT NYX: Primordial Log Intelligence
Filename: parser.py
Version: 1.0
Description: The "Data Cleaner." This module transforms messy, unstructured 
log strings into structured Python dictionaries using Regex. It is responsible 
for initial data extraction and populating the PID-to-IP tracker.
"""
import re
import config

def auth_line_cleaner(line, tracker):
    repeat_count = 1
    if "message repeated" in line:
        repeat_match = re.search(r"message repeated (\d+) times", line)
        if repeat_match:
            repeat_count = int(repeat_match.group(1)) + 1

    auth_match = re.search(config.AUTH_EVENT, line)
    if auth_match:
        pid = auth_match.group(2)
        ip = auth_match.group(5)
        tracker[pid] = ip
        return {
            "time" : auth_match.group(1),
            "id" : pid,
            "action" : auth_match.group(3),
            "user" : auth_match.group(4),
            "ip" : ip,
            "port" : auth_match.group(6),
            "count": repeat_count
        }
            
    session_match = re.search(config.AUTH_SESSION_EVENT, line)
    if session_match:
        return {
            "time" : session_match.group(1),
            "action" : session_match.group(2),
            "user" : session_match.group(3),
            "ip" : session_match.group(4),
            "count": repeat_count
        }
    
    sudo_match = re.search(config.AUTH_SUDO_EVENT, line)
    if sudo_match:
        return {
            "time" : sudo_match.group(1),
            "id" : sudo_match.group(2),
            "user" : sudo_match.group(3),
            "target_user" : sudo_match.group(4),
            "command" : sudo_match.group(5),
            "count": repeat_count
        }
    return None


# Placeholder for future expansion:
# TODO: Implement access_line_cleaner() for Web Server logs (v1.1)
# TODO: Implement syslog_line_cleaner() for Kernel/General logs (v1.2)