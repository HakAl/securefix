"""
Test to reproduce code duplication bug with real data.

This test uses actual fixes.json output to debug why imports and code
get duplicated when applying fixes.
"""
import tempfile
import os
from pathlib import Path
from securefix.mcp.code_patcher import apply_fixes_to_file, group_fixes_by_file


def test_weak_encryption_fix_duplication():
    """
    Reproduce duplication bug with weak_encryption fix.

    Issue: LLM-generated fix includes imports at the top, but code_patcher
    replaces only the function body, causing import duplication.
    """
    # Original vulnerable code
    original_code = """# test_vulnerable.py
\"\"\"
Comprehensive test file with various security vulnerabilities
for stress-testing SecureFix remediation engine.
\"\"\"

# ============================================================================
# Edge Cases & Corner Cases
# ============================================================================

# Obfuscated SQL injection
def get_user_data(table, uid):
    query = "SELECT * FROM " + table + " WHERE id=" + str(uid)
    cursor.execute(query)
    return cursor.fetchall()


# Nested dangerous operations
def execute_user_code(user_input):
    exec(compile(user_input, '<string>', 'exec'))


# Path traversal via Flask route
from flask import Flask, send_file
app = Flask(__name__)

@app.route('/admin/<path:file>')
def serve_file(file):
    return send_file(file)


# Multiple crypto weaknesses
from Crypto.Cipher import AES
import hashlib

def weak_encryption(data):
    key = hashlib.md5(b'weak').digest()  # Weak hash + hardcoded key
    cipher = AES.new(key, AES.MODE_ECB)  # Weak cipher mode
    return cipher.encrypt(data)
"""

    # Real remediation from fixes.json
    remediation = {
        "finding": {
            "type": "Weak Cryptography",
            "line": 37,  # Line where def weak_encryption starts
            "severity": "high",
            "confidence": "high",
            "snippet": "def weak_encryption(data):\nkey = hashlib.md5(b'weak').digest()  # Weak hash + hardcoded key\ncipher = AES.new(key, AES.MODE_ECB)  # Weak cipher mode",
            "description": "Use of weak MD5 hash for security. Consider usedforsecurity=False",
            "file": "test_vulnerable.py",
            "bandit_test_id": "B324"
        },
        "suggested_fix": "import hashlib\nfrom Crypto.Cipher import AES\n\ndef weak_encryption(data):\n    key = hashlib.md5(b'weak').digest()  # Weak hash + hardcoded key\n    cipher = AES.new(key, AES.MODE_ECB)  # Weak cipher mode\n    return cipher.encrypt(data.encode())",
        "explanation": "The original code used a weak hashing algorithm (MD5) and an insecure cipher mode (ECB).",
        "confidence": "High",
        "cwe_id": "CWE-202",
    }

    # Create temp file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, encoding='utf-8') as f:
        f.write(original_code)
        temp_path = f.name

    try:
        # Apply the fix
        result = apply_fixes_to_file(temp_path, [remediation])

        print("\n" + "="*70)
        print("ORIGINAL CODE:")
        print("="*70)
        print(original_code)

        print("\n" + "="*70)
        print("FIXED CODE:")
        print("="*70)
        print(result)

        print("\n" + "="*70)
        print("ANALYSIS:")
        print("="*70)

        # Check for issues
        import_count = result.count("import hashlib")
        from_count = result.count("from Crypto.Cipher import AES")
        function_count = result.count("def weak_encryption(data):")

        print(f"- 'import hashlib' appears {import_count} times (expected: 1)")
        print(f"- 'from Crypto.Cipher import AES' appears {from_count} times (expected: 1)")
        print(f"- 'def weak_encryption' appears {function_count} times (expected: 1)")

        # Check for syntax errors
        try:
            compile(result, '<string>', 'exec')
            print("- Code compiles: OK")
        except SyntaxError as e:
            print(f"- Code has syntax error: {e}")

        # Assertions to verify the bug
        assert import_count <= 2, f"Import duplication! Found {import_count} imports"
        assert from_count <= 2, f"Import duplication! Found {from_count} from imports"
        assert function_count == 1, f"Function duplication! Found {function_count} definitions"

        # This will likely fail:
        try:
            compile(result, '<string>', 'exec')
        except SyntaxError:
            assert False, "Generated code has syntax errors!"

    finally:
        os.unlink(temp_path)


def test_snippet_matching_issue():
    """
    Test that demonstrates the mismatch between finding.snippet and suggested_fix.

    Issue: finding.snippet is just the vulnerable code (3 lines)
           suggested_fix includes imports + full function (7 lines)
    """
    remediation = {
        "finding": {
            "line": 37,
            "snippet": "def weak_encryption(data):\nkey = hashlib.md5(b'weak').digest()  # Weak hash + hardcoded key\ncipher = AES.new(key, AES.MODE_ECB)  # Weak cipher mode",
        },
        "suggested_fix": "import hashlib\nfrom Crypto.Cipher import AES\n\ndef weak_encryption(data):\n    key = hashlib.md5(b'weak').digest()  # Weak hash + hardcoded key\n    cipher = AES.new(key, AES.MODE_ECB)  # Weak cipher mode\n    return cipher.encrypt(data.encode())",
    }

    old_lines = remediation['finding']['snippet'].split('\n')
    new_lines = remediation['suggested_fix'].split('\n')

    print(f"\nOLD SNIPPET ({len(old_lines)} lines):")
    print(remediation['finding']['snippet'])

    print(f"\nNEW SNIPPET ({len(new_lines)} lines):")
    print(remediation['suggested_fix'])

    print(f"\nPROBLEM:")
    print(f"- Old has {len(old_lines)} lines")
    print(f"- New has {len(new_lines)} lines")
    print(f"- New includes imports that should be deduplicated")
    print(f"- New has extra closing paren: 'data.encode()))'")


if __name__ == "__main__":
    print("Running code_patcher duplication test...\n")

    print("="*70)
    print("TEST 1: Snippet Matching Analysis")
    print("="*70)
    test_snippet_matching_issue()

    print("\n" + "="*70)
    print("TEST 2: Actual Code Patching")
    print("="*70)
    test_weak_encryption_fix_duplication()
