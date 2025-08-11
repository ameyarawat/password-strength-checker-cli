#!/usr/bin/env python3
"""
Password Strength Checker (CLI)

Evaluates password strength using multiple heuristics:
- Shannon entropy
- Character-set size entropy estimate
- Pattern analysis: repeats, sequences, keyboard sequences, years, common words
- Optional Have I Been Pwned k-anonymity breach check

Outputs human-readable text or JSON.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import sys
from dataclasses import dataclass, asdict
from getpass import getpass
from typing import Dict, List, Tuple

try:
    # Only used if --hibp is provided; import lazily in function too
    import urllib.request  # noqa: WPS433 (stdlib)
except Exception:  # pragma: no cover - safe fallback
    urllib = None  # type: ignore


# -------------------------- Utilities -------------------------- #


ANSI = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "red": "\033[31m",
    "yellow": "\033[33m",
    "green": "\033[32m",
    "blue": "\033[34m",
}


def colorize(text: str, color: str, use_color: bool) -> str:
    if not use_color:
        return text
    return f"{ANSI.get(color, '')}{text}{ANSI['reset']}"


def safe_stdin_read() -> str:
    data = sys.stdin.read()
    # Strip trailing newlines that can appear with echo/pipes
    return data.rstrip("\r\n")


# -------------------------- Models -------------------------- #


COMMON_WORDS = {
    "password",
    "admin",
    "qwerty",
    "letmein",
    "welcome",
    "iloveyou",
    "dragon",
    "monkey",
    "football",
    "baseball",
    "abc123",
    "trustno1",
    "starwars",
    "login",
    "master",
}

KEYBOARD_SEQUENCES = [
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890",
    "1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik,9ol.0p;/",
]


CHARSETS: Dict[str, str] = {
    "lower": "abcdefghijklmnopqrstuvwxyz",
    "upper": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "digits": "0123456789",
    # Symbols include common ASCII punctuation; adjust if needed
    "symbols": r"!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
    "space": " ",
}


@dataclass
class AnalysisResult:
    password_length: int
    shannon_bits_per_char: float
    shannon_total_bits: float
    charset_size: int
    charset_entropy_bits: float
    present_charsets: List[str]
    findings: List[str]
    score: int
    rating: str
    hibp_breached: bool
    hibp_count: int


# -------------------------- Analysis -------------------------- #


def compute_shannon_entropy_bits_per_char(text: str) -> float:
    if not text:
        return 0.0
    frequency: Dict[str, int] = {}
    for ch in text:
        frequency[ch] = frequency.get(ch, 0) + 1
    length = len(text)
    entropy = 0.0
    for count in frequency.values():
        p = count / length
        # Shannon entropy in bits per char
        entropy -= p * math.log2(p)
    return entropy


def detect_character_sets(text: str) -> Tuple[List[str], int]:
    present: List[str] = []
    charset_union = set()
    for name, chars in CHARSETS.items():
        if any(ch in chars for ch in text):
            present.append(name)
            charset_union.update(chars)
    return present, len(charset_union)


def estimate_charset_entropy_bits(text: str, charset_size: int) -> float:
    if not text or charset_size <= 1:
        return 0.0
    return len(text) * math.log2(charset_size)


def has_repeated_runs(text: str, min_run: int = 3) -> bool:
    if not text:
        return False
    run = 1
    for i in range(1, len(text)):
        if text[i] == text[i - 1]:
            run += 1
            if run >= min_run:
                return True
        else:
            run = 1
    return False


def contains_sequence(text: str, min_len: int = 4) -> bool:
    if len(text) < min_len:
        return False
    # Check ascending/descending sequences by ord value
    asc = 1
    desc = 1
    for i in range(1, len(text)):
        if ord(text[i]) - ord(text[i - 1]) == 1:
            asc += 1
            desc = 1
        elif ord(text[i]) - ord(text[i - 1]) == -1:
            desc += 1
            asc = 1
        else:
            asc = 1
            desc = 1
        if asc >= min_len or desc >= min_len:
            return True
    return False


def contains_keyboard_sequence(text: str, min_len: int = 4) -> bool:
    lowered = text.lower()
    for seq in KEYBOARD_SEQUENCES:
        if any(lowered[i : i + min_len] in (seq, seq[::-1]) for i in range(0, len(lowered) - min_len + 1)):
            return True
        # Also scan substrings longer than min_len
        for k in range(min_len + 1, min(len(lowered), len(seq)) + 1):
            if any(lowered[i : i + k] in (seq, seq[::-1]) for i in range(0, len(lowered) - k + 1)):
                return True
    return False


def contains_year(text: str) -> bool:
    return re.search(r"\b(19\d{2}|20\d{2})\b", text) is not None


def contains_common_words(text: str) -> List[str]:
    lowered = text.lower()
    found = sorted({w for w in COMMON_WORDS if w in lowered})
    return found


def hibp_query_count(password: str, timeout_seconds: int = 8) -> int:
    sha1_hex = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1_hex[:5]
    suffix = sha1_hex[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    req = urllib.request.Request(url, headers={"User-Agent": "pwd-strength-checker/1.0"})  # type: ignore[attr-defined]
    with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:  # type: ignore[attr-defined]
        body = resp.read().decode("utf-8", errors="replace")
    for line in body.splitlines():
        try:
            cand_suffix, count_str = line.split(":")
        except ValueError:
            continue
        if cand_suffix.strip().upper() == suffix:
            try:
                return int(count_str.strip())
            except ValueError:
                return 0
    return 0


def rate_score(score: int) -> str:
    mapping = {0: "Very Weak", 1: "Weak", 2: "Moderate", 3: "Strong", 4: "Very Strong"}
    return mapping.get(max(0, min(score, 4)), "Unknown")


def analyze_password(password: str, min_length: int, do_hibp: bool) -> AnalysisResult:
    length = len(password)
    shannon_bpc = compute_shannon_entropy_bits_per_char(password)
    shannon_total = shannon_bpc * length
    present_sets, charset_size = detect_character_sets(password)
    charset_bits = estimate_charset_entropy_bits(password, charset_size)

    findings: List[str] = []

    if length < min_length:
        findings.append(f"Short length (< {min_length})")
    if len(present_sets) <= 1:
        findings.append("Low character variety")
    if has_repeated_runs(password):
        findings.append("Contains repeated character runs")
    if contains_sequence(password):
        findings.append("Contains ascending/descending sequence")
    if contains_keyboard_sequence(password):
        findings.append("Contains keyboard sequence (e.g., qwerty)")
    if contains_year(password):
        findings.append("Contains year-like pattern (19xx/20xx)")
    common = contains_common_words(password)
    if common:
        findings.append(f"Contains common word(s): {', '.join(common)}")

    hibp_breached = False
    hibp_count = 0
    if do_hibp:
        try:
            hibp_count = hibp_query_count(password)
            hibp_breached = hibp_count > 0
            if hibp_breached:
                findings.append(f"Found in known breaches ({hibp_count} times)")
        except Exception:
            findings.append("HIBP check failed (network or API error)")

    # Score heuristic: start at 0, add points for good properties, subtract for issues
    score = 0
    if length >= min_length:
        score += 1
    if len(present_sets) >= 3:
        score += 1
    if shannon_bpc >= 3.0:  # ~8 effective characters (~3 bits/char) baseline
        score += 1
    if not findings:
        score += 1
    # Penalize severe issues
    if hibp_breached:
        score = max(0, score - 2)
    if contains_sequence(password) or contains_keyboard_sequence(password):
        score = max(0, score - 1)

    score = max(0, min(score, 4))
    rating = rate_score(score)

    return AnalysisResult(
        password_length=length,
        shannon_bits_per_char=round(shannon_bpc, 2),
        shannon_total_bits=round(shannon_total, 2),
        charset_size=charset_size,
        charset_entropy_bits=round(charset_bits, 2),
        present_charsets=present_sets,
        findings=findings,
        score=score,
        rating=rating,
        hibp_breached=hibp_breached,
        hibp_count=hibp_count,
    )


def build_suggestions(analysis: AnalysisResult, min_length: int) -> List[str]:
    suggestions: List[str] = []
    if analysis.password_length < min_length:
        suggestions.append(f"Increase length to at least {min_length}, preferably 16+")
    if len(analysis.present_charsets) < 3:
        suggestions.append("Use a mix of upper/lowercase, digits, and symbols")
    if any("year" in f.lower() for f in analysis.findings):
        suggestions.append("Avoid predictable years/dates")
    if any("sequence" in f.lower() for f in analysis.findings):
        suggestions.append("Break up sequences like 1234 or abcd")
    if any("repeated" in f.lower() for f in analysis.findings):
        suggestions.append("Avoid long runs of the same character")
    if any("common word" in f.lower() for f in analysis.findings):
        suggestions.append("Avoid common words or replace letters unpredictably")
    if analysis.hibp_breached:
        suggestions.append("Do not reuse breached passwords; choose a new one")
    if analysis.shannon_bits_per_char < 3.0:
        suggestions.append("Consider a passphrase of 3–4 random words")
    if not suggestions:
        suggestions.append("Looks good. Consider using a password manager to generate/store it")
    return suggestions


# -------------------------- CLI -------------------------- #


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Password Strength Checker (CLI)")
    parser.add_argument("--password", dest="password", help="Password value (prefer prompt or stdin)")
    parser.add_argument("--stdin", action="store_true", help="Read password from STDIN")
    parser.add_argument("--hibp", action="store_true", help="Check via Have I Been Pwned k-anonymity API")
    parser.add_argument("--min-length", type=int, default=12, help="Minimum recommended length (default: 12)")
    parser.add_argument("--json", dest="as_json", action="store_true", help="Output JSON")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    return parser.parse_args(argv)


def main(argv: List[str]) -> int:
    args = parse_args(argv)

    if args.stdin:
        password = safe_stdin_read()
    elif args.password is not None:
        password = str(args.password)
    else:
        password = getpass("Enter password to evaluate: ")

    # Safety: prevent accidental empty strings
    if password == "":
        print("No password provided.")
        return 2

    if args.hibp and urllib is None:
        print("Cannot perform HIBP check: urllib unavailable.")

    analysis = analyze_password(password=password, min_length=args.min_length, do_hibp=bool(args.hibp))
    suggestions = build_suggestions(analysis, args.min_length)

    if args.as_json:
        payload = asdict(analysis)
        payload["suggestions"] = suggestions
        print(json.dumps(payload, indent=2))
        return 0

    use_color = not args.no_color and sys.stdout.isatty()

    # Human-readable output
    score_line = f"Score: {analysis.score}/4 ({analysis.rating})"
    color = "green" if analysis.score >= 3 else ("yellow" if analysis.score == 2 else "red")
    print(colorize(score_line, color, use_color))
    print(f"Length: {analysis.password_length}")
    print(
        f"Entropy (Shannon): {analysis.shannon_bits_per_char} bits/char (total ~{analysis.shannon_total_bits} bits)"
    )
    charset_desc = (
        f"Character sets: {', '.join(analysis.present_charsets) or 'none'} (charset≈{analysis.charset_size})"
    )
    print(charset_desc)
    print(f"Charset-based entropy estimate: ~{analysis.charset_entropy_bits} bits")

    if analysis.findings:
        print("Findings:")
        for f in analysis.findings:
            print(f"  - {f}")
    else:
        print("Findings: none")

    if args.hibp:
        if analysis.hibp_breached:
            print(colorize(f"HIBP breaches: Found ({analysis.hibp_count})", "red", use_color))
        elif analysis.hibp_count == 0:
            print(colorize("HIBP breaches: Not found", "green", use_color))
        else:
            print("HIBP: Unable to determine")

    print("Suggestions:")
    for s in suggestions:
        print(f"  - {s}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))


