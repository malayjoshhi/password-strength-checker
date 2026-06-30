import math
import re
import hashlib
from typing import Dict, Any, List

COMMON_PATTERNS = [
    r"1234", r"qwerty", r"password", r"admin", r"welcome", r"letmein",
    r"abc123", r"0000", r"7777777", r"iloveyou"
]

class PasswordChecker:
    """
    Evaluates password strength based on entropy, pattern matching, 
    character diversity, and HaveIBeenPwned breach database lookup.
    """
    def __init__(self, password: str):
        self.password = password

    def calculate_entropy(self) -> float:
        """Calculates password entropy in bits."""
        pool_size = 0
        if re.search(r"[a-z]", self.password):
            pool_size += 26
        if re.search(r"[A-Z]", self.password):
            pool_size += 26
        if re.search(r"[0-9]", self.password):
            pool_size += 10
        if re.search(r"[^a-zA-Z0-9]", self.password):
            pool_size += 32

        if pool_size == 0 or len(self.password) == 0:
            return 0.0

        entropy = len(self.password) * math.log2(pool_size)
        return round(entropy, 2)

    def check_complexity(self) -> Dict[str, bool]:
        """Checks character set inclusion and length requirements."""
        return {
            "min_length_8": len(self.password) >= 8,
            "min_length_12": len(self.password) >= 12,
            "has_lowercase": bool(re.search(r"[a-z]", self.password)),
            "has_uppercase": bool(re.search(r"[A-Z]", self.password)),
            "has_digits": bool(re.search(r"[0-9]", self.password)),
            "has_symbols": bool(re.search(r"[^a-zA-Z0-9]", self.password))
        }

    def check_common_patterns(self) -> List[str]:
        """Flags predictable or common sequence patterns."""
        detected = []
        pwd_lower = self.password.lower()
        for pat in COMMON_PATTERNS:
            if pat in pwd_lower:
                detected.append(pat)
        return detected

    def check_pwned_api(self) -> int:
        """
        Queries HaveIBeenPwned API using k-Anonymity (SHA-1 prefix).
        Returns the number of times the password appeared in data breaches.
        """
        try:
            import urllib.request
            sha1_hash = hashlib.sha1(self.password.encode('utf-8')).hexdigest().upper()
            prefix, suffix = sha1_hash[:5], sha1_hash[5:]
            
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            req = urllib.request.Request(url, headers={'User-Agent': 'SecurityCheckTool'})
            
            with urllib.request.urlopen(req, timeout=3) as response:
                hashes = response.read().decode('utf-8').splitlines()
                for line in hashes:
                    h_suffix, count = line.split(':')
                    if h_suffix == suffix:
                        return int(count)
        except Exception:
            pass # Return 0 if network request fails or offline
        return 0

    def evaluate(self, check_breaches: bool = False) -> Dict[str, Any]:
        """Generates a complete security evaluation report."""
        entropy = self.calculate_entropy()
        complexity = self.check_complexity()
        patterns = self.check_common_patterns()
        breaches = self.check_pwned_api() if check_breaches else 0

        # Score calculation (0-100)
        score = min(100, int((entropy / 80) * 100))
        if patterns:
            score = max(0, score - 30)
        if breaches > 0:
            score = max(0, score - 50)

        if score < 40:
            rating = "WEAK"
        elif score < 75:
            rating = "MEDIUM"
        else:
            rating = "STRONG"

        return {
            "password": "*" * len(self.password),
            "length": len(self.password),
            "entropy_bits": entropy,
            "score": score,
            "rating": rating,
            "complexity": complexity,
            "patterns_detected": patterns,
            "pwned_breach_count": breaches
        }
