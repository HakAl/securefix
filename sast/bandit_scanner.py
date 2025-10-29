import subprocess
import json
import os
from typing import List, Dict, Any
from models import Finding
from sast.bandit_mapper import convert_bandit_result


def scan(path: str) -> List[Finding]:
    """
    Runs the Bandit scanner on the given path (file or directory).
    Bandit handles both automatically with -r flag.
    """
    print(f"Running SAST scan with Bandit on {path}...")

    command = [
        "bandit",
        "-r", path,
        "-f", "json",
    ]

    try:
        result = subprocess.run(command, capture_output=True, text=True)

        # Check if it actually failed (not just found issues)
        if result.returncode not in [0, 1]:  # 0 = no issues, 1 = issues found
            print(f"Bandit scan failed: {result.stderr}")
            return []

        # Parse JSON directly from stdout
        try:
            bandit_data = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            print(f"Error parsing Bandit output: {e}")
            return []

        # Transform the results into your internal Finding objects
        findings = [
            convert_bandit_result(res)
            for res in bandit_data.get("results", [])
        ]

        print(f"SAST scan complete. Found {len(findings)} issues.")
        return findings

    except FileNotFoundError:
        print("Error: 'bandit' command not found. Is it installed and in your PATH?")
        return []
    except subprocess.CalledProcessError as e:
        print(f"Bandit scan failed with error: {e.stderr}")
        return []