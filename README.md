# 🌑 Project-NYX
**Version: 1.0.0**

**NYX** is a high-speed, stateful forensic tool designed for Linux `auth.log` analysis. Unlike basic parsers, NYX uses look-ahead logic and PID tracking to provide an accurate map of brute-force attempts and successful security breaches.

## ⚡ Performance & Accuracy
* **High-Speed Engine:** Optimized to process **7,100+ lines in ~0.05s** (Benchmark: Apple M3 | Python 3.9.6).
* **Forensic Multiplier:** Corrects "hidden" telemetry. When logs show `message repeated X times`, NYX mathematically reconstructs the missing attempts to ensure 100% strike accuracy.
* **Stateful Attribution:** Uses PID tracking to link fragmented SSH sessions back to the originating IP, eliminating "Unknown IP" gaps in reports.
* **Native Compression Support:** Directly analyzes `.log.gz` (rotated) files without requiring manual extraction (+~0.01s overhead).

## 🛠 Features
* **Smart Detection:** Automatically flags **Bursts** (rapid-fire) and **High Volume** (long-term) threats.
* **Breach Tracking:** Identifies successful logins (`Accepted password`) that occur after a series of failed attempts.
* **Transparent Whitelisting:** Whitelisted IPs are tracked and reported with a `WHITELIST` status, ensuring authorized activity is monitored rather than hidden.

## 🧪 Validation & Benchmarking
To ensure reliability and transparency, NYX was benchmarked against a verified industry dataset:
* **Dataset:** [Elastic Security Analytics - Suspicious Login Activity](https://github.com/elastic/examples/blob/master/Machine%20Learning/Security%20Analytics%20Recipes/suspicious_login_activity/data/auth.log)
* **Scale:** Raw OpenSSH telemetry featuring complex brute-force patterns.
* **Integrity:** Verified 100% attribution accuracy across multi-session attempts and repeated-message suppression strings.

## 🚀 Roadmap
* [ ] **Web Server Analysis:** Support for `access.log` to detect directory brute-forcing and SQL injection attempts.

## 📦 Usage

1. **Setup:**
`git clone https://github.com/tushishvili/NYX.git && cd NYX`

2. **See Usage & Flags:**
`python3 nyx.py --help`

3. **View Results:** Check the formatted `.txt` report generated in the `reports/` folder.

## ⚙️ Config (config.py)
Modify detection sensitivity to match your environment:
* **THRESHOLD:** Hits required for a Burst alert.
* **TOTAL_VOLUME_THRESHOLD:** Total hits for High Volume detection.
* **WHITELIST:** Add trusted IPs to tag them as "Whitelist Activity".
* **CRITICAL_USERS:** List of high-value targets (e.g., `root`, `postgres`) to monitor closely.

---

## ⚖️ License & Copyright
Copyright (c) 2026 | **MIT License**
