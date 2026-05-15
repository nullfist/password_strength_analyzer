import re
import math
import secrets
import string
import time
from typing import Dict, List

try:
    import zxcvbn
    _HAS_ZXCVBN = True
except ImportError:
    _HAS_ZXCVBN = False

try:
    import bcrypt
    _HAS_BCRYPT = True
except ImportError:
    _HAS_BCRYPT = False

class PasswordStrengthAnalyzer:
    def __init__(self):
        # Heuristic patterns for manual detection
        self.common_patterns = [
            (r"^[a-zA-Z]+\d+$", "Sequential Alpha-Numeric"),
            (r"^[a-z]+$", "Lowercase only"),
            (r"^[A-Z]+$", "Uppercase only"),
            (r"^\d+$", "Numeric only"),
            (r"(.)\1{2,}", "Repeated Characters"),
            (r"(qwerty|asdf|zxcv|123456)", "Keyboard Walk / Sequence")
        ]

    def shannon_entropy(self, password: str) -> float:
        """Calculate Shannon entropy of the password."""
        if not password:
            return 0.0
        # Character pool size estimation
        pool_size = 0
        if re.search(r'[a-z]', password): pool_size += 26
        if re.search(r'[A-Z]', password): pool_size += 26
        if re.search(r'[0-9]', password): pool_size += 10
        if re.search(r'[^a-zA-Z0-9]', password): pool_size += 32
        
        if pool_size == 0: return 0.0
        
        # Bits of entropy = log2(pool_size^length)
        entropy = len(password) * math.log2(pool_size)
        return round(entropy, 2)

    def detect_patterns(self, password: str) -> List[str]:
        """Detect weak patterns using regex heuristics."""
        findings = []
        for pattern, label in self.common_patterns:
            if re.search(pattern, password, re.IGNORECASE):
                findings.append(label)
        return findings

    def estimate_crack_time(self, entropy: float) -> str:
        """Estimate offline GPU crack time."""
        # 10^10 guesses per second (Modern high-end GPU cluster)
        guesses_per_sec = 1e10
        total_seconds = (2 ** entropy) / guesses_per_sec
        
        if total_seconds < 1: return "Instantly"
        if total_seconds < 60: return f"{int(total_seconds)} seconds"
        if total_seconds < 3600: return f"{int(total_seconds/60)} minutes"
        if total_seconds < 86400: return f"{int(total_seconds/3600)} hours"
        if total_seconds < 31536000: return f"{int(total_seconds/86400)} days"
        return f"{int(total_seconds/31536000)} years"

    def score(self, password: str) -> Dict[str, any]:
        """Return a composite score and risk level."""
        entropy = self.shannon_entropy(password)
        patterns = self.detect_patterns(password)
        
        # Use zxcvbn if available for better scoring
        zxcvbn_score = 0
        feedback = []
        if _HAS_ZXCVBN:
            res = zxcvbn.zxcvbn(password)
            zxcvbn_score = res['score'] # 0-4
            feedback = res['feedback']['suggestions']
        
        # Weighted final score (0-100)
        base_score = min((entropy / 80) * 100, 100)
        
        # Penalty for detected patterns
        penalty = len(patterns) * 15
        final_score = max(base_score - penalty, 0)
        
        level = "SECURE"
        if final_score < 20: level = "CRITICAL"
        elif final_score < 40: level = "HIGH RISK"
        elif final_score < 60: level = "MODERATE"
        elif final_score < 85: level = "SECURE"
        else: level = "MILITARY-GRADE"
        
        return {
            "entropy_bits": entropy,
            "patterns": patterns,
            "crack_time": self.estimate_crack_time(entropy),
            "score": int(final_score),
            "level": level,
            "zxcvbn_tier": zxcvbn_score if _HAS_ZXCVBN else "N/A",
            "suggestions": feedback
        }

    def generate_secure(self, length: int = 16) -> str:
        """Generate a cryptographically secure password."""
        alphabet = string.ascii_letters + string.digits + string.punctuation
        return ''.join(secrets.choice(alphabet) for _ in range(length))

    def storage_demo(self, password: str):
        """Demonstrate secure hashing."""
        if not _HAS_BCRYPT:
            return "Bcrypt not installed."
        
        salt = bcrypt.gensalt(rounds=12)
        hashed = bcrypt.hashpw(password.encode(), salt)
        return {
            "plaintext": password,
            "salt": salt.decode(),
            "hashed": hashed.decode(),
            "algorithm": "Bcrypt (Blowfish)"
        }

if __name__ == "__main__":
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    
    console = Console()
    analyzer = PasswordStrengthAnalyzer()
    
    console.print(Panel("[bold green]Advanced Password Security Analyzer v1.0[/bold green]", subtitle="SOC Intelligence Engine"))
    
    pwd = console.input("[bold cyan]Enter password for audit:[/bold cyan] ")
    if not pwd:
        pwd = analyzer.generate_secure()
        console.print(f"[yellow]No input. Generated secure candidate:[/yellow] [bold magenta]{pwd}[/bold magenta]")
    
    result = analyzer.score(pwd)
    
    # Display Results
    table = Table(title="Analysis Results", show_header=False)
    table.add_row("Entropy Bits", f"{result['entropy_bits']} bits")
    table.add_row("Threat Level", f"[{'red' if result['score'] < 40 else 'green'}]{result['level']}[/]")
    table.add_row("Security Score", f"{result['score']}/100")
    table.add_row("Estimated Crack Time", f"[bold yellow]{result['crack_time']}[/]")
    
    console.print(table)
    
    if result['patterns']:
        console.print("\n[bold red]Detected Weak Patterns:[/bold red]")
        for p in result['patterns']:
            console.print(f"  • {p}")
            
    if result['suggestions']:
        console.print("\n[bold blue]Security Recommendations:[/bold blue]")
        for s in result['suggestions']:
            console.print(f"  • {s}")

    # Hashing Demo
    console.print("\n[bold cyan]Secure Storage Simulation (Bcrypt):[/bold cyan]")
    demo = analyzer.storage_demo(pwd)
    if isinstance(demo, dict):
        console.print(f"  [dim]Hash:[/dim] [green]{demo['hashed']}[/green]")
        console.print("  [dim]Result:[/dim] Successfully salted and hashed for secure DB storage.")
