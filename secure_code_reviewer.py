#!/usr/bin/env python3
"""
Task 3: Secure Coding Reviewer & Vulnerability Scanner
------------------------------------------------------
CodeAlpha Cybersecurity Internship Task 3

A Python Static Application Security Testing (SAST) tool that scans source code files
(Python, JavaScript, C/C++) for common OWASP vulnerabilities, hardcoded secrets,
and insecure coding practices. Generates terminal reports and HTML audit logs.
"""

import os
import re
import sys
import json
import argparse
from datetime import datetime

# Check for colorama
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLOR = True
except ImportError:
    COLOR = False

def col(text, color_code):
    return f"{color_code}{text}{Style.RESET_ALL}" if COLOR else text

# Vulnerability Patterns Dictionary
SECURITY_PATTERNS = [
    {
        "id": "SEC-001",
        "name": "Hardcoded Secret / Password / API Key",
        "severity": "HIGH",
        "category": "CWE-798: Use of Hard-coded Credentials",
        "pattern": r'(?i)(api[_-]?key|secret|password|passwd|auth[_-]?token|aws[_-]?key)\s*[:=]\s*["\'][A-Za-z0-9_/\-+=]{6,}["\']',
        "description": "Hardcoded secrets stored directly in source code can be extracted by unauthorized users or leaked via version control repositories.",
        "recommendation": "Move secrets into environment variables (e.g., os.getenv('API_KEY')) or external secret vaults (HashiCorp Vault, AWS Secrets Manager)."
    },
    {
        "id": "SEC-002",
        "name": "Potential SQL Injection Vulnerability",
        "severity": "HIGH",
        "category": "CWE-89: SQL Injection",
        "pattern": r'(?i)(select|insert|update|delete|from)\s+.*?\+\s*|\%s.*?\%\s*\(|f["\'].*?SELECT.*?\{',
        "description": "Constructing SQL queries dynamically via string concatenation or unescaped formatting allows malicious SQL input manipulation.",
        "recommendation": "Use parameterized queries / prepared statements (e.g. cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))) or an ORM (SQLAlchemy)."
    },
    {
        "id": "SEC-003",
        "name": "Dangerous Code Execution / Insecure Deserialization",
        "severity": "CRITICAL",
        "category": "CWE-95 / CWE-502: Insecure Deserialization & Code Injection",
        "pattern": r'\b(eval|exec)\s*\(|\bpickle\.loads\s*\(|\byaml\.unsafe_load\s*\(',
        "description": "Functions like eval(), exec(), and pickle.loads() execute arbitrary bytecode and allow Remote Code Execution (RCE).",
        "recommendation": "Avoid eval/exec completely. Use safer parsing mechanisms such as ast.literal_eval() for Python data structures or json.loads()."
    },
    {
        "id": "SEC-004",
        "name": "Command Injection Vulnerability",
        "severity": "HIGH",
        "category": "CWE-78: OS Command Injection",
        "pattern": r'\bos\.system\s*\(|\bsubprocess\.(Popen|call|run)\s*\(.*?shell\s*=\s*True',
        "description": "Executing system shell commands with un-sanitized user input allows attackers to run arbitrary OS commands.",
        "recommendation": "Avoid using shell=True in subprocess. Pass arguments as a list of strings: subprocess.run(['ls', '-l'], shell=False)."
    },
    {
        "id": "SEC-005",
        "name": "Weak Cryptographic Hash Function",
        "severity": "MEDIUM",
        "category": "CWE-327: Use of a Broken Cryptographic Algorithm",
        "pattern": r'\bhashlib\.(md5|sha1)\s*\(|\bMD5\s*\(|\bSHA1\s*\(',
        "description": "MD5 and SHA-1 algorithms are cryptographically broken and vulnerable to collision attacks.",
        "recommendation": "Upgrade to secure hashing algorithms such as SHA-256 (hashlib.sha256()) or argon2 / bcrypt for passwords."
    },
    {
        "id": "SEC-006",
        "name": "Potential Cross-Site Scripting (XSS)",
        "severity": "MEDIUM",
        "category": "CWE-79: Cross-Site Scripting (XSS)",
        "pattern": r'\.innerHTML\s*=|\bdangerouslySetInnerHTML\b|document\.write\s*\(',
        "description": "Directly assigning unsanitized strings to DOM HTML elements allows execution of malicious JavaScript.",
        "recommendation": "Use element.textContent or element.innerText to insert user-controlled plain text safely into the DOM."
    }
]

class CodeReviewer:
    def __init__(self, target_path):
        self.target_path = target_path
        self.findings = []
        self.scanned_files = 0

    def scan(self):
        print("=" * 75)
        print(col("     CODEALPHA CYBERSECURITY - SECURE CODING REVIEW TOOL", Fore.CYAN if COLOR else ""))
        print("=" * 75)
        print(f"[*] Target Path: {os.path.abspath(self.target_path)}")
        print(f"[*] Scanning for OWASP vulnerabilities & hardcoded secrets...\n")

        if os.path.isfile(self.target_path):
            self._scan_file(self.target_path)
        elif os.path.isdir(self.target_path):
            for root, _, files in os.walk(self.target_path):
                for file in files:
                    if file.endswith(('.py', '.js', '.jsx', '.ts', '.c', '.cpp', '.h', '.php', '.java')):
                        self._scan_file(os.path.join(root, file))

        self._print_summary()

    def _scan_file(self, file_path):
        self.scanned_files += 1
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            for line_idx, line in enumerate(lines, 1):
                clean_line = line.strip()
                # Skip pure comments
                if clean_line.startswith('#') or clean_line.startswith('//'):
                    continue

                for rule in SECURITY_PATTERNS:
                    match = re.search(rule["pattern"], line)
                    if match:
                        finding = {
                            "rule_id": rule["id"],
                            "vulnerability": rule["name"],
                            "severity": rule["severity"],
                            "category": rule["category"],
                            "file": os.path.relpath(file_path),
                            "line_num": line_idx,
                            "snippet": clean_line[:120],
                            "description": rule["description"],
                            "recommendation": rule["recommendation"]
                        }
                        self.findings.append(finding)
                        self._print_finding(finding)

        except Exception as e:
            print(col(f"[X] Error reading file {file_path}: {e}", Fore.RED if COLOR else ""))

    def _print_finding(self, f):
        sev = f['severity']
        sev_color = Fore.RED if sev in ["CRITICAL", "HIGH"] else Fore.YELLOW
        print(f"[{col(sev, sev_color if COLOR else '')}] {col(f['vulnerability'], Fore.CYAN if COLOR else '')}")
        print(f" |- File: {f['file']}:{f['line_num']}")
        print(f" |- Snippet: {f['snippet']}")
        print(f" \\- Fix: {f['recommendation']}\n")

    def _print_summary(self):
        print("=" * 75)
        print(col("                       AUDIT SUMMARY RESULT", Fore.GREEN if COLOR else ""))
        print("=" * 75)
        print(f"[*] Files Scanned: {self.scanned_files}")
        print(f"[*] Total Vulnerabilities Identified: {len(self.findings)}")
        
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in self.findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1

        for sev, c in counts.items():
            print(f"    |- {sev}: {c}")

        print("=" * 75)

    def generate_html_report(self, output_filename="security_audit_report.html"):
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        findings_html = ""
        for f in self.findings:
            sev_class = "sev-critical" if f['severity'] == "CRITICAL" else ("sev-high" if f['severity'] == "HIGH" else "sev-medium")
            findings_html += f"""
            <div class="card {sev_class}">
                <div class="card-header">
                    <span class="badge {sev_class}">{f['severity']}</span>
                    <h3>[{f['rule_id']}] {f['vulnerability']}</h3>
                </div>
                <div class="card-body">
                    <p><strong>Location:</strong> <code>{f['file']}:{f['line_num']}</code></p>
                    <p><strong>Category:</strong> {f['category']}</p>
                    <div class="snippet"><code>{f['snippet']}</code></div>
                    <p><strong>Description:</strong> {f['description']}</p>
                    <div class="remediation"><strong>Recommendation:</strong> {f['recommendation']}</div>
                </div>
            </div>
            """

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Code Security Audit Report - CodeAlpha</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 40px; }}
        .container {{ max-width: 1000px; margin: 0 auto; }}
        h1 {{ color: #38bdf8; border-bottom: 2px solid #334155; padding-bottom: 15px; }}
        .summary-box {{ background: #1e293b; padding: 20px; border-radius: 10px; margin-bottom: 30px; display: flex; gap: 20px; justify-content: space-around; }}
        .sum-item {{ text-align: center; }}
        .sum-num {{ font-size: 2rem; font-weight: bold; color: #38bdf8; }}
        .card {{ background: #1e293b; border-left: 6px solid #94a3b8; border-radius: 8px; margin-bottom: 20px; padding: 20px; }}
        .sev-critical {{ border-left-color: #ef4444; }}
        .sev-high {{ border-left-color: #f97316; }}
        .sev-medium {{ border-left-color: #eab308; }}
        .badge {{ padding: 4px 10px; border-radius: 4px; font-weight: bold; font-size: 0.8rem; float: right; color: white; }}
        .badge.sev-critical {{ background: #ef4444; }}
        .badge.sev-high {{ background: #f97316; }}
        .badge.sev-medium {{ background: #eab308; }}
        .snippet {{ background: #090d16; padding: 12px; border-radius: 6px; font-family: monospace; margin: 10px 0; color: #38bdf8; }}
        .remediation {{ background: rgba(56, 189, 248, 0.1); padding: 12px; border-radius: 6px; border: 1px solid rgba(56, 189, 248, 0.3); margin-top: 10px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Static Code Security Audit Report</h1>
        <p>Generated on: {now_str} | CodeAlpha Cybersecurity Task 3</p>

        <div class="summary-box">
            <div class="sum-item"><div class="sum-num">{self.scanned_files}</div>Files Scanned</div>
            <div class="sum-item"><div class="sum-num">{len(self.findings)}</div>Total Issues</div>
        </div>

        <h2>Audit Findings</h2>
        {findings_html if self.findings else '<p>No security vulnerabilities detected!</p>'}
    </div>
</body>
</html>"""

        with open(output_filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        print(col(f"[+] HTML Security Audit Report saved to: {os.path.abspath(output_filename)}", Fore.GREEN if COLOR else ""))

def main():
    parser = argparse.ArgumentParser(description="Task 3: Secure Coding Reviewer (CodeAlpha Cybersecurity)")
    parser.add_argument("path", nargs="?", default=".", help="File or directory path to scan")
    parser.add_argument("-o", "--html", default="security_audit_report.html", help="Output HTML report path")
    args = parser.parse_args()

    reviewer = CodeReviewer(target_path=args.path)
    reviewer.scan()
    reviewer.generate_html_report(output_filename=args.html)

if __name__ == "__main__":
    main()
