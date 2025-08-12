import os
import sys

# Ensure repository root is on sys.path for module imports when CI sets a different cwd
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from password_strength_checker import analyze_password, build_suggestions


def test_very_weak_short_password():
    result = analyze_password("abc", min_length=12, do_hibp=False)
    assert result.password_length == 3
    assert result.score <= 1
    assert any("Short length" in f for f in result.findings)


def test_detect_common_patterns():
    pwd = "Password1234"  # nosec B105: Test example, not a real password
    result = analyze_password(pwd, min_length=8, do_hibp=False)
    assert any("common word" in f.lower() for f in result.findings)
    assert any("sequence" in f.lower() for f in result.findings)


def test_strong_passphrase_like():
    pwd = "Correct-Horse-Battery-Staple-987!"  # nosec B105: Test example, not a real password
    result = analyze_password(pwd, min_length=12, do_hibp=False)
    assert result.password_length >= 12
    assert result.score >= 2
    suggestions = build_suggestions(result, 12)
    assert isinstance(suggestions, list)
