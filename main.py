import argparse
import sys
import getpass
from checker import PasswordChecker

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
RESET = "\033[0m"

BANNER = f"""{CYAN}
  ___  _   ___ _____  _____   ___  ___   ___ 
 | _ \/_\ / __/ __\ \/ / _ \ / _ \| _ \/ __|
 |  _/ _ \\__ \__ \>  <| (_) | (_) |   /\__ \\
 |_|/_/ \\_\___/___/_/\_\\___/ \___/|_|_\|___/
{RESET}      Password Strength & Breach Analyzer v1.0
"""

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="Advanced Password Strength & Breach Analyzer")
    parser.add_argument("-p", "--password", help="Password string to test (Leave empty for secure masked prompt)")
    parser.add_argument("--check-breaches", action="store_true", help="Query HaveIBeenPwned API for data breaches")
    args = parser.parse_args()

    pwd = args.password
    if not pwd:
        pwd = getpass.getpass("Enter password to analyze: ")

    if not pwd:
        print(f"{RED}[-] No password provided.{RESET}")
        sys.exit(1)

    print("\n[*] Analyzing password security...")
    checker = PasswordChecker(pwd)
    report = checker.evaluate(check_breaches=args.check_breaches)

    rating_color = GREEN if report['rating'] == 'STRONG' else (YELLOW if report['rating'] == 'MEDIUM' else RED)
    
    print("-" * 50)
    print(f"Password Rating: {rating_color}{report['rating']}{RESET} (Score: {report['score']}/100)")
    print(f"Entropy        : {report['entropy_bits']} bits")
    print(f"Length         : {report['length']} characters")
    print("-" * 50)
    print("Character Breakdown:")
    for check, passed in report['complexity'].items():
        mark = f"{GREEN}✓{RESET}" if passed else f"{RED}✗{RESET}"
        print(f"  [{mark}] {check.replace('_', ' ').title()}")
    
    if report['patterns_detected']:
        print(f"\n{RED}[!] Weak patterns found: {', '.join(report['patterns_detected'])}{RESET}")

    if args.check_breaches:
        if report['pwned_breach_count'] > 0:
            print(f"\n{RED}[⚠️] ALERT: Password found in {report['pwned_breach_count']} data breaches!{RESET}")
        else:
            print(f"\n{GREEN}[✓] Clean! Password not found in known data breaches.{RESET}")
    print("-" * 50)

if __name__ == "__main__":
    main()
