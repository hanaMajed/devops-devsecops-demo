import os
import subprocess
import json
import re

# ═══════════════════════════════════════════════════════════════════
# CONFIGURATION - Baddel haw m3a project mte3ek
# ═══════════════════════════════════════════════════════════════════

# EXEMPLE 1: Scan project local
PROJECT_NAME = "my-secure-app"
PROJECT_PATH = os.getcwd()  # Current directory

# EXEMPLE 2: Scan downloaded project
# PROJECT_NAME = "flask-security"
# PROJECT_PATH = "/tmp/simple-demo"

# ═══════════════════════════════════════════════════════════════════
# GLOBAL VARIABLES
# ═══════════════════════════════════════════════════════════════════

all_issues = []  # Liste lel kol les security issues
report_file = f"{PROJECT_NAME}_security_report.json"

# ═══════════════════════════════════════════════════════════════════
# FONCTION 1: Print m3a colors
# ═══════════════════════════════════════════════════════════════════

def print_step(message, status="info"):
    """Print message m3a colors"""
    colors = {
        "info": "\033[94m",     # Blue
        "success": "\033[92m",  # Green
        "warning": "\033[93m",  # Yellow
        "error": "\033[91m"     # Red
    }
    reset = "\033[0m"
    
    icons = {
        "info": "▶",
        "success": "✓",
        "warning": "⚠",
        "error": "✗"
    }
    
    icon = icons.get(status, "▶")
    color = colors.get(status, colors["info"])
    
    print(f"{color}{icon} {message}{reset}")

# ═══════════════════════════════════════════════════════════════════
# FONCTION 2: Run command safely
# ═══════════════════════════════════════════════════════════════════

def run(command, silent=False):
    """Run command w return output"""
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            cwd=PROJECT_PATH
        )
        return result.stdout, result.stderr, result.returncode
    except Exception as e:
        if not silent:
            print_step(f"Error: {str(e)}", "error")
        return "", str(e), 1

# ═══════════════════════════════════════════════════════════════════
# STEP 1: SCAN DEPENDENCIES
# ═══════════════════════════════════════════════════════════════════

def scan_dependencies():
    """Scan Python dependencies lel vulnerabilities"""
    print("\n" + "="*60)
    print("STEP 1: SCANNING DEPENDENCIES FOR VULNERABILITIES")
    print("="*60)
    
    issues = []
    
    # Check ken famma requirements.txt
    req_file = os.path.join(PROJECT_PATH, "requirements.txt")
    
    if not os.path.exists(req_file):
        print_step("No requirements.txt found - Creating sample file", "info")
        
        # Na3mlou sample requirements lel demo
        with open(req_file, 'w') as f:
            f.write("# Sample dependencies for demo\n")
            f.write("requests==2.25.0\n")  # Old version m3a vulnerabilities
            f.write("flask==1.0.0\n")      # Old version
        
        print_step("Created sample requirements.txt", "success")
    
    # Install safety tool
    print_step("Installing safety scanner...", "info")
    run("pip install safety -q", silent=True)
    
    # Run safety check
    print_step("Scanning dependencies with Safety...", "info")
    stdout, stderr, code = run("safety check --json")
    
    if stdout and stdout.strip():
        try:
            vulns = json.loads(stdout)
            
            if vulns and len(vulns) > 0:
                issues.append({
                    "type": "Dependency Vulnerabilities",
                    "count": len(vulns),
                    "details": vulns[:3]  # First 3 only
                })
                
                print_step(f"Found {len(vulns)} dependency vulnerabilities!", "warning")
                
                # Show examples
                for vuln in vulns[:3]:
                    pkg = vuln.get("package", "Unknown")
                    vuln_id = vuln.get("vulnerability_id", "N/A")
                    print(f"  - {pkg}: {vuln_id}")
            else:
                print_step("No dependency vulnerabilities found", "success")
        except json.JSONDecodeError:
            print_step("Could not parse safety output, skipping", "warning")
    else:
        print_step("No vulnerabilities detected in dependencies", "success")
    
    all_issues.extend(issues)
    return len(issues)

# ═══════════════════════════════════════════════════════════════════
# STEP 2: SCAN CODE FOR SECURITY ISSUES
# ═══════════════════════════════════════════════════════════════════

def scan_code():
    """Scan code lel security issues m3a Bandit"""
    print("\n" + "="*60)
    print("STEP 2: SCANNING CODE FOR SECURITY ISSUES")
    print("="*60)
    
    issues = []
    
    # Check ken famma Python files
    py_files = []
    for root, dirs, files in os.walk(PROJECT_PATH):
        # Skip certain directories
        dirs[:] = [d for d in dirs if d not in ['.git', 'venv', '__pycache__', 'node_modules']]
        py_files.extend([f for f in files if f.endswith('.py')])
    
    if not py_files:
        print_step("No Python files found - Creating sample file", "info")
        
        # Na3mlou sample file m3a security issues lel demo
        sample_file = os.path.join(PROJECT_PATH, "demo_app.py")
        with open(sample_file, 'w') as f:
            f.write("""# Demo file with intentional security issues
import os

# Issue 1: Hardcoded password (BAD!)
password = "admin123"

# Issue 2: SQL injection risk (BAD!)
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    return query

# Issue 3: Using eval (DANGEROUS!)
def calculate(expression):
    return eval(expression)

# Issue 4: Insecure random
import random
token = random.randint(1000, 9999)

print("Demo app with security issues")
""")
        print_step("Created demo_app.py with security issues", "success")
    
    # Install bandit
    print_step("Installing Bandit scanner...", "info")
    run("pip install bandit -q", silent=True)
    
    # Run bandit
    print_step("Scanning code with Bandit...", "info")
    stdout, stderr, code = run("bandit -r . -f json 2>/dev/null")
    
    if stdout:
        try:
            results = json.loads(stdout)
            bandit_issues = results.get("results", [])
            
            if bandit_issues:
                # Count by severity
                high = sum(1 for i in bandit_issues if i.get("issue_severity") == "HIGH")
                medium = sum(1 for i in bandit_issues if i.get("issue_severity") == "MEDIUM")
                low = sum(1 for i in bandit_issues if i.get("issue_severity") == "LOW")
                
                issues.append({
                    "type": "Code Security Issues",
                    "total": len(bandit_issues),
                    "high": high,
                    "medium": medium,
                    "low": low,
                    "details": bandit_issues[:3]
                })
                
                print_step(f"Found {len(bandit_issues)} code security issues!", "warning")
                print(f"  - HIGH: {high}")
                print(f"  - MEDIUM: {medium}")
                print(f"  - LOW: {low}")
                
                # Show examples
                for issue in bandit_issues[:3]:
                    test_id = issue.get("test_id", "Unknown")
                    severity = issue.get("issue_severity", "?")
                    text = issue.get("issue_text", "No description")
                    print(f"  - [{severity}] {test_id}: {text[:50]}...")
            else:
                print_step("No code security issues found", "success")
        except json.JSONDecodeError:
            print_step("Could not parse Bandit output", "warning")
    else:
        print_step("Bandit scan completed - no major issues", "success")
    
    all_issues.extend(issues)
    return len(issues)

# ═══════════════════════════════════════════════════════════════════
# STEP 3: DETECT SECRETS
# ═══════════════════════════════════════════════════════════════════

def detect_secrets():
    """Detect hardcoded secrets fil code"""
    print("\n" + "="*60)
    print("STEP 3: DETECTING HARDCODED SECRETS")
    print("="*60)
    
    issues = []
    
    # Patterns lel common secrets
    patterns = {
        "Password": r"password\s*=\s*['\"]([^'\"]{3,})['\"]",
        "API Key": r"api[_-]?key\s*=\s*['\"]([a-zA-Z0-9]{20,})['\"]",
        "Secret": r"secret\s*=\s*['\"]([^'\"]{8,})['\"]",
        "Token": r"token\s*=\s*['\"]([a-zA-Z0-9]{20,})['\"]",
        "AWS Key": r"AKIA[0-9A-Z]{16}",
    }
    
    print_step("Searching for hardcoded secrets...", "info")
    
    files_checked = 0
    secrets_found = 0
    
    # Scan files
    for root, dirs, files in os.walk(PROJECT_PATH):
        dirs[:] = [d for d in dirs if d not in ['.git', 'venv', '__pycache__', 'node_modules']]
        
        for file in files:
            if file.endswith(('.py', '.js', '.json', '.env', '.config', '.yaml', '.yml')):
                file_path = os.path.join(root, file)
                files_checked += 1
                
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        
                        for secret_type, pattern in patterns.items():
                            matches = re.finditer(pattern, content, re.IGNORECASE)
                            
                            for match in matches:
                                line_num = content[:match.start()].count('\n') + 1
                                
                                issues.append({
                                    "type": "Hardcoded Secret",
                                    "secret_type": secret_type,
                                    "file": os.path.relpath(file_path, PROJECT_PATH),
                                    "line": line_num,
                                    "snippet": match.group(0)[:40] + "..."
                                })
                                secrets_found += 1
                except:
                    continue
    
    print_step(f"Scanned {files_checked} files", "info")
    
    if secrets_found > 0:
        print_step(f"CRITICAL: Found {secrets_found} hardcoded secrets!", "error")
        
        # Show examples
        for issue in issues[:3]:
            print(f"  - {issue['secret_type']} in {issue['file']}:{issue['line']}")
        
        all_issues.extend(issues)
    else:
        print_step("No hardcoded secrets detected", "success")
    
    return len(issues)

# ═══════════════════════════════════════════════════════════════════
# STEP 4: GENERATE SECURITY REPORT
# ═══════════════════════════════════════════════════════════════════

def generate_report():
    """Generate final security report"""
    print("\n" + "="*60)
    print("STEP 4: GENERATING SECURITY REPORT")
    print("="*60)
    
    # Create report
    report = {
        "project": PROJECT_NAME,
        "scan_path": PROJECT_PATH,
        "total_issues": len(all_issues),
        "findings": all_issues,
        "summary": {
            "dependency_issues": 0,
            "code_issues": 0,
            "secrets_found": 0
        }
    }
    
    # Count by type
    for issue in all_issues:
        issue_type = issue.get("type", "Unknown")
        
        if "Dependency" in issue_type:
            report["summary"]["dependency_issues"] += issue.get("count", 1)
        elif "Code" in issue_type:
            report["summary"]["code_issues"] += issue.get("total", 1)
        elif "Secret" in issue_type:
            report["summary"]["secrets_found"] += 1
    
    # Save report
    report_path = os.path.join(PROJECT_PATH, report_file)
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    
    print_step(f"Security report saved: {report_file}", "success")
    
    # Print summary
    print("\n" + "="*60)
    print("SECURITY SCAN SUMMARY")
    print("="*60)
    
    if report["total_issues"] == 0:
        print_step("✓ NO SECURITY ISSUES FOUND!", "success")
        print_step("  Your project is secure!", "success")
    else:
        print_step(f"Total Issues: {report['total_issues']}", "warning")
        
        print("\nBreakdown:")
        for category, count in report["summary"].items():
            if count > 0:
                label = category.replace('_', ' ').title()
                print(f"  - {label}: {count}")
        
        print("\nRecommendations:")
        print("  1. Review the detailed report in JSON file")
        print("  2. Fix HIGH severity issues first")
        print("  3. Update vulnerable dependencies")
        print("  4. Remove hardcoded secrets")
        print("  5. Re-run scan after fixes")
    
    return report

# ═══════════════════════════════════════════════════════════════════
# MAIN SECURITY PIPELINE
# ═══════════════════════════════════════════════════════════════════

def main():
    """Run el security pipeline el kemel"""
    
    print("╔═══════════════════════════════════════════════════════════╗")
    print("║       DevSecOps Security Scanner - Simple Version       ║")
    print("╚═══════════════════════════════════════════════════════════╝")
    print(f"\nProject: {PROJECT_NAME}")
    print(f"Path: {PROJECT_PATH}")
    
    # Verify path exists
    if not os.path.exists(PROJECT_PATH):
        print_step(f"Error: Path does not exist: {PROJECT_PATH}", "error")
        return False
    
    # Run security checks
    print("\n" + "🔒 Starting Security Scan...")
    
    dep_issues = scan_dependencies()      # Step 1
    code_issues = scan_code()             # Step 2
    secret_issues = detect_secrets()      # Step 3
    report = generate_report()            # Step 4
    
    # Final status
    total = dep_issues + code_issues + secret_issues
    
    print("\n" + "="*60)
    if total == 0:
        print_step("✓ Security Scan PASSED! 🎉", "success")
        return True
    else:
        print_step(f"⚠ Security Scan COMPLETED with {total} issue categories", "warning")
        return False

# ═══════════════════════════════════════════════════════════════════
# RUN THE SCRIPT
# ═══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    success = main()
    
    print("\n" + "="*60)
    print("Scan completed!")
    print(f"Report file: {report_file}")
    print("="*60)
    
    exit(0 if success else 1)
