"""
PROJECT NYX: Primordial Log Intelligence
Filename: config.py
Version: 1.0
Description: Global configuration including detection rules, 
security thresholds, and regex patterns.
"""

# --- TIME CONSTANTS (Seconds) ---
MINUTE = 60
HOUR = 60 * MINUTE
DAY = 24 * HOUR

# --- DETECTION RULES ---
THRESHOLD =  5              # Strikes needed for a Burst alert
TOTAL_VOLUME_THRESHOLD = 15  # Total hits to trigger High Volume alert
MAX_BURST_GAP = 30      # Gap between hits in a Burst
VOLUME_WINDOW = DAY         # Analysis window for Volume detection

# --- REGEX PATTERNS ---
# Matches: Timestamp, PID, Action, User, IP, Port
AUTH_EVENT = r'^(\w{3}\s+\d+\s\d{2}:\d{2}:\d{2}).*?sshd\[(\d+)\]:.*?(Failed password|Accepted password|maximum authentication attempts exceeded) for (?:invalid user )?(\w+) from (\d{1,3}(?:\.\d{1,3}){3}) port (\d{1,5})'

# Matches: Timestamp, Session Action, User, IP
AUTH_SESSION_EVENT = r'^(\w{3}\s+\d+\s\d{2}:\d{2}:\d{2}).*session (opened|closed) for user (\w+).*?from\s+(\d{1,3}(?:\.\d{1,3}){3})'

# Matches: Timestamp, PID, User, Target User, Command
AUTH_SUDO_EVENT = r'^(\w{3}\s+\d+\s\d{2}:\d{2}:\d{2}).*?sudo\[(\d+)\]:\s+(\w+)\s+:\s+TTY=.*?;\s+USER=(\w+)\s+;\s+COMMAND=(.*)'

# --- ACCESS CONTROL ---
WHITELIST = [
    "127.0.0.1"
]

# --- TARGETS ---
CRITICAL_USERS = ["root", "admin", "bin", "daemon", "dbadmin"]