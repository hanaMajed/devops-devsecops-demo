#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════════
    SCRIPT DEVSECOPS - SECURITY AUTOMATION FIL CI/CD PIPELINE
═══════════════════════════════════════════════════════════════════
Hal script ya3mel security scanning w vulnerability checks:
  1. Dependency vulnerability scanning
  2. Static Application Security Testing (SAST)
  3. Secret detection (passwords, API keys)
  4. Docker security scanning
  5. Security report generation
"""

import subprocess
import json
import os
import sys
import re
from datetime import datetime

# ═══════════════════════════════════════════════════════════════════
# PARTIE 1: CLASSE MTA3 DEVSECOPS AUTOMATION
# ═══════════════════════════════════════════════════════════════════

class DevSecOpsAutomation:
    """
    Classe principale lel automation mta3 Security checks fil DevOps pipeline

    Hal classe ta3mel:
    - Dependency scanning lel vulnerabilities
    - Static code analysis (SAST)
    - Secret detection fil code
    - Docker security scanning
    - Report generation
    """

    def __init__(self, project_name, project_path):
        """
        Constructor: Ya3mel initialization lel security scanner

        Args:
            project_name (str): Esm el project mte3ek
            project_path (str): Path wel fih el code (ex: /home/user/myapp)

        Example:
            devsecops = DevSecOpsAutomation("my-app", "/path/to/code")
        """
        self.project_name = project_name
        self.project_path = project_path
        self.security_report = f"{project_name}_security_report.json"
        self.vulnerabilities = []  # Liste lel kol les vulnerabilities eli yitla9ew

        print(f"✓ DevSecOps Scanner initialized for: {project_name}")
        print(f"  Scanning path: {project_path}")

    # ═══════════════════════════════════════════════════════════════════
    # PARTIE 2: LOGGING W UTILITY FUNCTIONS
    # ═══════════════════════════════════════════════════════════════════

    def log(self, message, level="INFO"):
        """
        Fonction lel logging m3a color coding fil terminal

        Args:
            message (str): El message bich yit3arredh
            level (str): Niveau mta3 el log (INFO/SUCCESS/WARNING/ERROR)

        Colors:
            - INFO: Blue (معلومات عادية)
            - SUCCESS: Green (نجاح)
            - WARNING: Yellow (تحذير)
            - ERROR: Red (خطأ)
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # ANSI color codes lel terminal
        colors = {
            "INFO": "\033[94m",     # Blue
            "SUCCESS": "\033[92m",  # Green
            "WARNING": "\033[93m",  # Yellow
            "ERROR": "\033[91m",    # Red
            "END": "\033[0m"        # Reset color
        }

        color = colors.get(level, colors["INFO"])
        reset = colors["END"]

        # Print m3a colors
        print(f"{color}[{timestamp}] [{level}] {message}{reset}")

    def run_command(self, command, description):
        """
        Execute shell command w capture output

        Args:
            command (str): El command bich yitnaféth
            description (str): Wasf mta3 el command

        Returns:
            tuple: (stdout, stderr, return_code)
                - stdout: Output mta3 el command
                - stderr: Error messages
                - return_code: 0 = success, other = failure
        """
        self.log(f"Running: {description}", "INFO")

        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                cwd=self.project_path  # Run fil project directory
            )
            return result.stdout, result.stderr, result.returncode

        except Exception as e:
            self.log(f"Error executing command: {str(e)}", "ERROR")
            return None, str(e), 1

    # ═══════════════════════════════════════════════════════════════════
    # PARTIE 3: DEPENDENCY VULNERABILITY SCANNING
    # ═══════════════════════════════════════════════════════════════════

    def scan_dependencies(self):
        """
        STEP 1: Scan dependencies lel known vulnerabilities

        Kifech tikhdim:
            1. Python: Yisti3mil "safety" bich ya3mel scan lel pip packages
            2. Node.js: Yisti3mil "npm audit" bich ya3mel scan lel npm packages
            3. Yikhazen el results fil vulnerabilities list

        Returns:
            list: Liste mta3 vulnerabilities eli itla9ew

        Tools used:
            - safety: Python package vulnerability scanner
            - npm audit: Node.js package vulnerability scanner
        """
        self.log("=" * 60, "INFO")
        self.log("STEP 1: SCANNING DEPENDENCIES FOR VULNERABILITIES", "INFO")
        self.log("=" * 60, "INFO")

        findings = []

        # ═══════════════════════════════════════════════════════════
        # Scan Python Dependencies (requirements.txt)
        # ═══════════════════════════════════════════════════════════

        req_file = os.path.join(self.project_path, "requirements.txt")

        if os.path.exists(req_file):
            self.log("Found requirements.txt - Scanning Python dependencies...", "INFO")

            # Install safety tool ken mich mawjoud
            self.log("Installing safety scanner...", "INFO")
            subprocess.run("pip install safety -q", shell=True)

            # Run safety check
            stdout, stderr, code = self.run_command(
                "safety check --json",
                "Python dependency vulnerability scan with Safety"
            )

            if stdout:
                try:
                    # Parse JSON output
                    vulnerabilities = json.loads(stdout)

                    if vulnerabilities:
                        # Famma vulnerabilities
                        findings.append({
                            "type": "Python Dependencies",
                            "tool": "Safety",
                            "count": len(vulnerabilities),
                            "details": vulnerabilities
                        })
                        self.log(
                            f"⚠ Found {len(vulnerabilities)} Python vulnerabilities",
                            "WARNING"
                        )

                        # Print details 3la kol vulnerability
                        for vuln in vulnerabilities[:3]:  # First 3 only
                            pkg_name = vuln.get("package", "Unknown")
                            vuln_id = vuln.get("vulnerability_id", "Unknown")
                            self.log(f"  - {pkg_name}: {vuln_id}", "WARNING")
                    else:
                        self.log("✓ No Python vulnerabilities found", "SUCCESS")

                except json.JSONDecodeError:
                    self.log("Could not parse safety output", "WARNING")
        else:
            self.log("No requirements.txt found - Skipping Python scan", "INFO")

        # ═══════════════════════════════════════════════════════════
        # Scan Node.js Dependencies (package.json)
        # ═══════════════════════════════════════════════════════════

        package_file = os.path.join(self.project_path, "package.json")

        if os.path.exists(package_file):
            self.log("Found package.json - Scanning Node.js dependencies...", "INFO")

            # Run npm audit
            stdout, stderr, code = self.run_command(
                "npm audit --json",
                "Node.js dependency vulnerability scan with npm audit"
            )

            if stdout:
                try:
                    # Parse JSON output
                    audit_result = json.loads(stdout)

                    # Get vulnerability counts by severity
                    vuln_counts = audit_result.get("metadata", {}).get("vulnerabilities", {})
                    total_vulns = sum(vuln_counts.values())

                    if total_vulns > 0:
                        # Famma vulnerabilities
                        findings.append({
                            "type": "Node.js Dependencies",
                            "tool": "npm audit",
                            "count": total_vulns,
                            "severity_breakdown": vuln_counts,
                            "details": audit_result
                        })

                        self.log(
                            f"⚠ Found {total_vulns} Node.js vulnerabilities",
                            "WARNING"
                        )

                        # Print breakdown by severity
                        for severity, count in vuln_counts.items():
                            if count > 0:
                                self.log(f"  - {severity}: {count}", "WARNING")
                    else:
                        self.log("✓ No Node.js vulnerabilities found", "SUCCESS")

                except json.JSONDecodeError:
                    self.log("Could not parse npm audit output", "WARNING")
        else:
            self.log("No package.json found - Skipping Node.js scan", "INFO")

        # Save findings
        self.vulnerabilities.extend(findings)

        return findings

    # ═══════════════════════════════════════════════════════════════════
    # PARTIE 4: STATIC APPLICATION SECURITY TESTING (SAST)
    # ═══════════════════════════════════════════════════════════════════

    def static_code_analysis(self):
        """
        STEP 2: Static Application Security Testing (SAST)

        Kifech tikhdim:
            1. Yfattech 3la kol les Python files fil project
            2. Yisti3mil "Bandit" bich ya3mel security analysis lel code
            3. Yilka security issues (SQL injection, hardcoded passwords, etc)

        Returns:
            list: Liste mta3 security issues fil code

        Security issues detected:
            - SQL injection vulnerabilities
            - Use of insecure functions
            - Hardcoded passwords
            - Weak cryptography
            - etc.
        """
        self.log("=" * 60, "INFO")
        self.log("STEP 2: STATIC APPLICATION SECURITY TESTING (SAST)", "INFO")
        self.log("=" * 60, "INFO")

        findings = []

        # ═══════════════════════════════════════════════════════════
        # Check ken famma Python files
        # ═══════════════════════════════════════════════════════════

        python_files = []
        for root, dirs, files in os.walk(self.project_path):
            # Skip directories ma ista7kouch scan
            dirs[:] = [d for d in dirs if d not in ['.git', 'venv', '__pycache__', 'node_modules']]

            # Collect Python files
            python_files.extend([
                os.path.join(root, f) for f in files if f.endswith('.py')
            ])

        if python_files:
            self.log(f"Found {len(python_files)} Python files to scan", "INFO")

            # ═══════════════════════════════════════════════════════
            # Install w run Bandit scanner
            # ═══════════════════════════════════════════════════════

            self.log("Installing Bandit scanner...", "INFO")
            subprocess.run("pip install bandit -q", shell=True)

            self.log("Running Bandit security scan...", "INFO")
            stdout, stderr, code = self.run_command(
                "bandit -r . -f json",
                "Python code security analysis with Bandit"
            )

            if stdout:
                try:
                    # Parse Bandit results
                    results = json.loads(stdout)
                    issues = results.get("results", [])

                    if issues:
                        # Group issues by severity
                        severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}

                        for issue in issues:
                            severity = issue.get("issue_severity", "UNKNOWN")
                            if severity in severity_counts:
                                severity_counts[severity] += 1

                        findings.append({
                            "type": "Python Code Security Issues",
                            "tool": "Bandit",
                            "count": len(issues),
                            "severity_breakdown": severity_counts,
                            "details": issues
                        })

                        self.log(
                            f"⚠ Found {len(issues)} security issues in Python code",
                            "WARNING"
                        )

                        # Print severity breakdown
                        for severity, count in severity_counts.items():
                            if count > 0:
                                self.log(f"  - {severity}: {count}", "WARNING")

                        # Show example issues
                        self.log("Example issues:", "INFO")
                        for issue in issues[:3]:
                            test_id = issue.get("test_id", "Unknown")
                            desc = issue.get("issue_text", "No description")
                            self.log(f"  - [{test_id}] {desc}", "WARNING")
                    else:
                        self.log("✓ No code security issues found", "SUCCESS")

                except json.JSONDecodeError:
                    self.log("Could not parse Bandit output", "WARNING")
        else:
            self.log("No Python files found - Skipping SAST", "INFO")

        # Save findings
        self.vulnerabilities.extend(findings)

        return findings

    # ═══════════════════════════════════════════════════════════════════
    # PARTIE 5: SECRET DETECTION
    # ═══════════════════════════════════════════════════════════════════

    def check_secrets(self):
        """
        STEP 3: Check lel hardcoded secrets (passwords, API keys, tokens)

        Kifech tikhdim:
            1. Define regex patterns lel common secrets
            2. Scan kol les files fil project
            3. Check ken famma matches m3a el patterns
            4. Report any secrets found

        Returns:
            list: Liste mta3 secrets eli itla9ew

        Secrets detected:
            - AWS Access Keys
            - API Keys
            - Passwords
            - Private Keys (SSH, SSL)
            - OAuth Tokens
            - Database connection strings
        """
        self.log("=" * 60, "INFO")
        self.log("STEP 3: SCANNING FOR HARDCODED SECRETS", "INFO")
        self.log("=" * 60, "INFO")

        findings = []

        # ═══════════════════════════════════════════════════════════
        # Define regex patterns lel common secrets
        # ═══════════════════════════════════════════════════════════

        secret_patterns = {
            "AWS Access Key": r"AKIA[0-9A-Z]{16}",
            "Generic API Key": r"api[_-]?key['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9]{32,}",
            "Password in Code": r"password['\"]?\s*[:=]\s*['\"][^'\"]{3,}['\"]",
            "Private Key": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
            "OAuth Token": r"oauth[_-]?token['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9]{20,}",
            "Generic Secret": r"secret['\"]?\s*[:=]\s*['\"][^'\"]{8,}['\"]",
            "Database URL": r"(mysql|postgresql|mongodb):\/\/[^\s]+",
        }

        self.log(f"Searching for {len(secret_patterns)} types of secrets...", "INFO")

        # ═══════════════════════════════════════════════════════════
        # Scan kol les files
        # ═══════════════════════════════════════════════════════════

        files_scanned = 0

        for root, dirs, files in os.walk(self.project_path):
            # Skip directories ma ista7kouch scan
            dirs[:] = [d for d in dirs if d not in [
                '.git', 'node_modules', '__pycache__', 'venv',
                '.venv', 'dist', 'build'
            ]]

            for file in files:
                # Scan only relevant file types
                if file.endswith((
                    '.py', '.js', '.jsx', '.ts', '.tsx',
                    '.json', '.env', '.config', '.yaml',
                    '.yml', '.xml', '.ini', '.conf'
                )):
                    file_path = os.path.join(root, file)
                    files_scanned += 1

                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()

                            # Check kol pattern
                            for secret_type, pattern in secret_patterns.items():
                                matches = re.finditer(pattern, content, re.IGNORECASE)

                                for match in matches:
                                    # Calculate line number
                                    line_num = content[:match.start()].count('\n') + 1

                                    # Get context (el sater wel fih el secret)
                                    lines = content.split('\n')
                                    context_line = lines[line_num - 1] if line_num <= len(lines) else ""

                                    findings.append({
                                        "type": "Hardcoded Secret",
                                        "secret_type": secret_type,
                                        "file": os.path.relpath(file_path, self.project_path),
                                        "line": line_num,
                                        "snippet": match.group(0)[:50] + "...",
                                        "context": context_line.strip()[:100]
                                    })

                    except Exception as e:
                        # Skip files eli ma yinqrawech
                        continue

        self.log(f"Scanned {files_scanned} files", "INFO")

        # ═══════════════════════════════════════════════════════════
        # Report results
        # ═══════════════════════════════════════════════════════════

        if findings:
            self.log(
                f"⚠ CRITICAL: Found {len(findings)} potential secrets in code!",
                "ERROR"
            )

            # Group by secret type
            secret_counts = {}
            for finding in findings:
                stype = finding["secret_type"]
                secret_counts[stype] = secret_counts.get(stype, 0) + 1

            self.log("Breakdown by type:", "WARNING")
            for stype, count in secret_counts.items():
                self.log(f"  - {stype}: {count}", "WARNING")

            # Show examples
            self.log("Example findings:", "WARNING")
            for finding in findings[:3]:
                self.log(
                    f"  - {finding['secret_type']} in {finding['file']}:{finding['line']}",
                    "WARNING"
                )

            self.vulnerabilities.extend(findings)
        else:
            self.log("✓ No hardcoded secrets detected", "SUCCESS")

        return findings

    # ═══════════════════════════════════════════════════════════════════
    # PARTIE 6: DOCKER SECURITY SCANNING
    # ═══════════════════════════════════════════════════════════════════

    def docker_security_scan(self):
        """
        STEP 4: Docker Image Security Scanning

        Kifech tikhdim:
            1. Check ken famma Dockerfile
            2. Analyze Dockerfile lel security best practices
            3. Report issues

        Returns:
            list: Liste mta3 Docker security issues

        Checks performed:
            - Using :latest tag (bad practice)
            - Running as root user
            - Copying entire directory
            - Missing .dockerignore
            - Exposed sensitive ports
        """
        self.log("=" * 60, "INFO")
        self.log("STEP 4: DOCKER IMAGE SECURITY SCANNING", "INFO")
        self.log("=" * 60, "INFO")

        findings = []

        # ═══════════════════════════════════════════════════════════
        # Check ken famma Dockerfile
        # ═══════════════════════════════════════════════════════════

        dockerfile_path = os.path.join(self.project_path, "Dockerfile")

        if not os.path.exists(dockerfile_path):
            self.log("No Dockerfile found - Skipping Docker scan", "INFO")
            return findings

        self.log("Found Dockerfile - Analyzing security...", "INFO")

        # ═══════════════════════════════════════════════════════════
        # Read w analyze Dockerfile
        # ═══════════════════════════════════════════════════════════

        with open(dockerfile_path, 'r') as f:
            dockerfile_content = f.read()
            dockerfile_lines = dockerfile_content.split('\n')

        issues = []

        # Check 1: Using :latest tag
        if "FROM" in dockerfile_content and ":latest" in dockerfile_content:
            issues.append({
                "severity": "MEDIUM",
                "issue": "Using ':latest' tag in FROM statement",
                "recommendation": "Specify exact version tags (e.g., FROM python:3.9.7)",
                "reason": "Latest tag can change unexpectedly and break builds"
            })

        # Check 2: Running as root
        if "USER root" in dockerfile_content or "USER" not in dockerfile_content:
            issues.append({
                "severity": "HIGH",
                "issue": "Container running as root user",
                "recommendation": "Add 'USER nonroot' or create a non-root user",
                "reason": "Running as root is a security risk"
            })

        # Check 3: Copying entire directory
        if "COPY . ." in dockerfile_content or "ADD . ." in dockerfile_content:
            issues.append({
                "severity": "MEDIUM",
                "issue": "Copying entire directory with 'COPY . .'",
                "recommendation": "Use specific COPY commands and .dockerignore file",
                "reason": "May include sensitive files or unnecessary data"
            })

        # Check 4: Missing .dockerignore
        dockerignore_path = os.path.join(self.project_path, ".dockerignore")
        if not os.path.exists(dockerignore_path):
            issues.append({
                "severity": "LOW",
                "issue": "Missing .dockerignore file",
                "recommendation": "Create .dockerignore to exclude unnecessary files",
                "reason": "Reduces image size and prevents sensitive file inclusion"
            })

        # Check 5: Exposed sensitive ports
        sensitive_ports = ["22", "3306", "5432", "27017", "6379"]
        for line in dockerfile_lines:
            if line.strip().startswith("EXPOSE"):
                for port in sensitive_ports:
                    if port in line:
                        issues.append({
                            "severity": "HIGH",
                            "issue": f"Exposing sensitive port {port}",
                            "recommendation": f"Avoid exposing port {port} or use internal networking",
                            "reason": "Database/SSH ports should not be publicly exposed"
                        })

        # Check 6: Hardcoded secrets
        secret_keywords = ["password", "secret", "key", "token"]
        for i, line in enumerate(dockerfile_lines, 1):
            for keyword in secret_keywords:
                if keyword.upper() in line.upper() and "=" in line:
                    issues.append({
                        "severity": "CRITICAL",
                        "issue": f"Possible hardcoded secret on line {i}",
                        "recommendation": "Use environment variables or Docker secrets",
                        "reason": "Hardcoded secrets in Dockerfile are visible in image layers"
                    })
                    break

        # ═══════════════════════════════════════════════════════════
        # Report results
        # ═══════════════════════════════════════════════════════════

        if issues:
            findings.append({
                "type": "Dockerfile Security Issues",
                "count": len(issues),
                "issues": issues
            })

            self.log(
                f"⚠ Found {len(issues)} Dockerfile security issues",
                "WARNING"
            )

            # Count by severity
            severity_counts = {}
            for issue in issues:
                sev = issue["severity"]
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            for severity, count in severity_counts.items():
                self.log(f"  - {severity}: {count}", "WARNING")

            # Show critical/high issues
            critical_issues = [i for i in issues if i["severity"] in ["CRITICAL", "HIGH"]]
            if critical_issues:
                self.log("Critical/High severity issues:", "ERROR")
                for issue in critical_issues[:3]:
                    self.log(f"  - {issue['issue']}", "ERROR")

            self.vulnerabilities.extend(findings)
        else:
            self.log("✓ Dockerfile follows security best practices", "SUCCESS")

        return findings

    # ═══════════════════════════════════════════════════════════════════
    # PARTIE 7: SECURITY REPORT GENERATION
    # ═══════════════════════════════════════════════════════════════════

    def generate_report(self):
        """
        STEP 5: Generate rapport mfassel 3al security findings

        Kifech tikhdim:
            1. Yijma3 kol les findings men kol les scans
            2. Ya3mel summary mta3 el results
            3. Yikhazen el report fi JSON file
            4. Ydhher summary fil console

        Returns:
            dict: El security report el kemel

        Report includes:
            - Total vulnerability count
            - Breakdown by type
            - Severity levels
            - Detailed findings
            - Recommendations
        """
        self.log("=" * 60, "INFO")
        self.log("STEP 5: GENERATING SECURITY REPORT", "INFO")
        self.log("=" * 60, "INFO")

        # ═══════════════════════════════════════════════════════════
        # Create report structure
        # ═══════════════════════════════════════════════════════════

        report = {
            "project": self.project_name,
            "scan_date": datetime.now().isoformat(),
            "scan_path": self.project_path,
            "total_vulnerabilities": len(self.vulnerabilities),
            "findings": self.vulnerabilities,
            "summary": {
                "dependency_issues": 0,
                "code_issues": 0,
                "secrets_found": 0,
                "docker_issues": 0
            },
            "severity_summary": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0
            }
        }

        # ═══════════════════════════════════════════════════════════
        # Calculate summary statistics
        # ═══════════════════════════════════════════════════════════

        for finding in self.vulnerabilities:
            finding_type = finding.get("type", "Unknown")

            if "Dependencies" in finding_type:
                report["summary"]["dependency_issues"] += finding.get("count", 1)
            elif "Code Security" in finding_type:
                report["summary"]["code_issues"] += finding.get("count", 1)
            elif "Secret" in finding_type:
                report["summary"]["secrets_found"] += 1
            elif "Docker" in finding_type:
                report["summary"]["docker_issues"] += finding.get("count", 1)

        # ═══════════════════════════════════════════════════════════
        # Save JSON report
        # ═══════════════════════════════════════════════════════════

        report_path = os.path.join(self.project_path, self.security_report)

        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)

        self.log(f"✓ Security report saved to: {report_path}", "SUCCESS")

        # ═══════════════════════════════════════════════════════════
        # Print console summary
        # ═══════════════════════════════════════════════════════════

        self.log("=" * 60, "INFO")
        self.log("SECURITY SCAN SUMMARY", "INFO")
        self.log("=" * 60, "INFO")

        # Overall status
        if report["total_vulnerabilities"] == 0:
            self.log("✓ NO SECURITY ISSUES FOUND", "SUCCESS")
            self.log("  Your project passed all security checks!", "SUCCESS")
        else:
            self.log(
                f"⚠ TOTAL ISSUES FOUND: {report['total_vulnerabilities']}",
                "ERROR"
            )

        # Breakdown
        self.log("\nBreakdown by Category:", "INFO")
        for category, count in report["summary"].items():
            if count > 0:
                self.log(f"  - {category.replace('_', ' ').title()}: {count}", "WARNING")

        # Recommendations
        if report["total_vulnerabilities"] > 0:
            self.log("\nRecommendations:", "INFO")
            self.log("  1. Review the detailed report in JSON file", "INFO")
            self.log("  2. Fix critical and high severity issues first", "INFO")
            self.log("  3. Update vulnerable dependencies", "INFO")
            self.log("  4. Remove any hardcoded secrets", "INFO")
            self.log("  5. Re-run scan after fixes", "INFO")

        return report

    # ═══════════════════════════════════════════════════════════════════
    # PARTIE 8: MAIN SECURITY PIPELINE EXECUTION
    # ═══════════════════════════════════════════════════════════════════

    def run_security_pipeline(self):
        """
        FONCTION PRINCIPALE: Execute el security pipeline el kemel

        Pipeline steps:
            1. Dependency vulnerability scanning
            2. Static code analysis (SAST)
            3. Secret detection
            4. Docker security scanning
            5. Report generation

        Returns:
            bool: True ken ma fammech critical issues, False otherwise
        """
        self.log("*" * 60, "INFO")
        self.log(f"STARTING DEVSECOPS PIPELINE FOR: {self.project_name}", "INFO")
        self.log("*" * 60, "INFO")

        start_time = datetime.now()
        self.log(f"Scan started at: {start_time.strftime('%Y-%m-%d %H:%M:%S')}", "INFO")

        # ═══════════════════════════════════════════════════════════
        # Execute kol les security checks
        # ═══════════════════════════════════════════════════════════

        self.scan_dependencies()          # Step 1
        self.static_code_analysis()       # Step 2
        self.check_secrets()              # Step 3
        self.docker_security_scan()       # Step 4

        # ═══════════════════════════════════════════════════════════
        # Generate final report
        # ═══════════════════════════════════════════════════════════

        report = self.generate_report()   # Step 5

        # ═══════════════════════════════════════════════════════════
        # Calculate statistics
        # ═══════════════════════════════════════════════════════════

        duration = (datetime.now() - start_time).total_seconds()

        self.log("*" * 60, "INFO")
        self.log(f"Security scan completed in {duration:.2f} seconds", "INFO")
        self.log("*" * 60, "INFO")

        # ═══════════════════════════════════════════════════════════
        # Determine if project is secure
        # ═══════════════════════════════════════════════════════════

        # Count critical issues
        critical_count = 0
        for finding in self.vulnerabilities:
            if isinstance(finding, dict):
                # Check severity fil details
                if "issues" in finding:
                    for issue in finding["issues"]:
                        if issue.get("severity") in ["CRITICAL", "HIGH"]:
                            critical_count += 1

        has_critical_issues = critical_count > 0 or len(self.vulnerabilities) > 10

        if has_critical_issues:
            self.log(
                f"⚠ Project has {critical_count} critical/high issues",
                "ERROR"
            )
            return False
        else:
            self.log("✓ Project passed security scan", "SUCCESS")
            return True


# ═══════════════════════════════════════════════════════════════════
# PARTIE 9: MAIN EXECUTION SCRIPT
# ═══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    """
    Main execution block

    Bich tisti3mlou:
        1. Baddel PROJECT_NAME w PROJECT_PATH
        2. Run: python devsecops_script.py
        3. Check el security report
    """

    print("╔═══════════════════════════════════════════════════════════╗")
    print("║       DevSecOps Security Scanner - Starting...          ║")
    print("╚═══════════════════════════════════════════════════════════╝")
    print()

    # ═══════════════════════════════════════════════════════════════
    # CONFIGURATION - Baddel haw m3a el settings mte3ek
    # ═══════════════════════════════════════════════════════════════

    PROJECT_NAME = "my-secure-app"  # Esm el project
    PROJECT_PATH = os.getcwd()      # Current directory (aw path specific)

    # Bich tisti3mil path specific:
    # PROJECT_PATH = "/home/user/my-project"

    # ═══════════════════════════════════════════════════════════════
    # Verify project path exists
    # ═══════════════════════════════════════════════════════════════

    if not os.path.exists(PROJECT_PATH):
        print(f"❌ Error: Project path does not exist: {PROJECT_PATH}")
        sys.exit(1)

    print(f"Configuration:")
    print(f"  Project: {PROJECT_NAME}")
    print(f"  Path: {PROJECT_PATH}")
    print()

    # ═══════════════════════════════════════════════════════════════
    # Create DevSecOps Instance
    # ═══════════════════════════════════════════════════════════════

    devsecops = DevSecOpsAutomation(PROJECT_NAME, PROJECT_PATH)

    # ═══════════════════════════════════════════════════════════════
    # Run the Security Pipeline
    # ═══════════════════════════════════════════════════════════════

    is_secure = devsecops.run_security_pipeline()

    # ═══════════════════════════════════════════════════════════════
    # Exit with appropriate status code
    # ═══════════════════════════════════════════════════════════════
    # Exit code 0 = secure/passed
    # Exit code 1 = vulnerabilities found

    print()
    if is_secure:
        print("╔═══════════════════════════════════════════════════════════╗")
        print("║           ✓ Security Scan Passed!                       ║")
        print("║              No critical issues found                    ║")
        print("╚═══════════════════════════════════════════════════════════╝")
        sys.exit(0)
    else:
        print("╔═══════════════════════════════════════════════════════════╗")
        print("║           ⚠ Security Issues Found!                      ║")
        print("║         Please review the security report               ║")
        print("╚═══════════════════════════════════════════════════════════╝")
        sys.exit(1)
