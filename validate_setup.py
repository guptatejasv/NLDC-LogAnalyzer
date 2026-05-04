"""
Setup validation script
Checks if the environment is properly configured
"""

import sys
import os
from pathlib import Path

# Colors for output
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
RESET = '\033[0m'
BOLD = '\033[1m'

def check_python_version():
    """Check Python version"""
    print(f"\n{BOLD}1. Python Version{RESET}")
    version = sys.version_info
    if version.major == 3 and version.minor >= 8:
        print(f"  {GREEN}✓{RESET} Python {version.major}.{version.minor} (Required: 3.8+)")
        return True
    else:
        print(f"  {RED}✗{RESET} Python {version.major}.{version.minor} (Required: 3.8+)")
        return False

def check_dependencies():
    """Check if required packages are installed"""
    print(f"\n{BOLD}2. Dependencies{RESET}")
    required = ['pandas', 'requests', 'dotenv', 'pydantic']
    all_present = True
    
    for package in required:
        try:
            __import__(package if package != 'dotenv' else 'dotenv')
            print(f"  {GREEN}✓{RESET} {package}")
        except ImportError:
            print(f"  {RED}✗{RESET} {package} - Install with: pip install {package}")
            all_present = False
    
    return all_present

def check_directories():
    """Check if required directories exist"""
    print(f"\n{BOLD}3. Directory Structure{RESET}")
    base_path = Path(__file__).parent
    required_dirs = ['src', 'config', 'data', 'logs', 'cache']
    all_exist = True
    
    for dir_name in required_dirs:
        dir_path = base_path / dir_name
        if dir_path.exists():
            print(f"  {GREEN}✓{RESET} {dir_name}/")
        else:
            print(f"  {RED}✗{RESET} {dir_name}/ - Missing directory")
            all_exist = False
    
    return all_exist

def check_files():
    """Check if required files exist"""
    print(f"\n{BOLD}4. Configuration Files{RESET}")
    base_path = Path(__file__).parent
    required_files = {
        '.env': 'Environment variables',
        'requirements.txt': 'Dependencies list',
        'README.md': 'Documentation',
        'data/logs.csv': 'Sample data'
    }
    all_exist = True
    
    for file_name, description in required_files.items():
        file_path = base_path / file_name
        if file_path.exists():
            print(f"  {GREEN}✓{RESET} {file_name} ({description})")
        else:
            print(f"  {YELLOW}⚠{RESET} {file_name} ({description}) - Missing")
            all_exist = False
    
    return all_exist

def check_env_config():
    """Check if .env file has API keys configured"""
    print(f"\n{BOLD}5. API Configuration{RESET}")
    base_path = Path(__file__).parent
    env_file = base_path / '.env'
    
    if not env_file.exists():
        print(f"  {RED}✗{RESET} .env file not found")
        return False
    
    with open(env_file, 'r') as f:
        content = f.read()
    
    vt_key_exists = 'VT_API_KEY=' in content and 'your_virustotal' not in content
    abuse_key_exists = 'ABUSE_API_KEY=' in content and 'your_abuseipdb' not in content
    
    if vt_key_exists:
        print(f"  {GREEN}✓{RESET} VirusTotal API key configured")
    else:
        print(f"  {YELLOW}⚠{RESET} VirusTotal API key - Not configured (optional)")
    
    if abuse_key_exists:
        print(f"  {GREEN}✓{RESET} AbuseIPDB API key configured")
    else:
        print(f"  {YELLOW}⚠{RESET} AbuseIPDB API key - Not configured (optional)")
    
    return True

def check_csv_format():
    """Check if sample CSV has correct format"""
    print(f"\n{BOLD}6. Sample Data Format{RESET}")
    base_path = Path(__file__).parent
    csv_file = base_path / 'data' / 'logs.csv'
    
    if not csv_file.exists():
        print(f"  {RED}✗{RESET} Sample CSV not found")
        return False
    
    with open(csv_file, 'r') as f:
        header = f.readline().strip()
    
    required_columns = ['Source IP', 'Destination IP', 'Port']
    has_columns = all(col in header for col in required_columns)
    
    if has_columns:
        print(f"  {GREEN}✓{RESET} CSV format is valid")
        print(f"     Columns: {header}")
        return True
    else:
        print(f"  {RED}✗{RESET} CSV format is invalid")
        print(f"     Expected: Source IP, Destination IP, Port")
        print(f"     Found: {header}")
        return False

def print_summary(results):
    """Print validation summary"""
    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}VALIDATION SUMMARY{RESET}")
    print(f"{BOLD}{'='*60}{RESET}")
    
    passed = sum(1 for r in results.values() if r)
    total = len(results)
    
    print(f"\nPassed: {passed}/{total}")
    
    if passed == total:
        print(f"\n{GREEN}{BOLD}✓ All checks passed! Ready to use.{RESET}")
        print(f"\nTo get started:")
        print(f"  1. Configure API keys in .env (optional)")
        print(f"  2. Run: python main.py")
    else:
        print(f"\n{YELLOW}{BOLD}⚠ Some checks failed. See above for details.{RESET}")
        print(f"\nTo fix issues:")
        print(f"  1. Install missing dependencies: pip install -r requirements.txt")
        print(f"  2. Check directory structure")
        print(f"  3. Review README.md for setup instructions")

def main():
    """Run all validation checks"""
    print(f"{BOLD}{YELLOW}Log Analyzer AI - Setup Validation{RESET}\n")
    
    results = {
        'Python Version': check_python_version(),
        'Dependencies': check_dependencies(),
        'Directories': check_directories(),
        'Files': check_files(),
        'API Configuration': check_env_config(),
        'CSV Format': check_csv_format(),
    }
    
    print_summary(results)

if __name__ == '__main__':
    main()
