from sast.detectors.secrets import detect_secrets, SECRET_PATTERNS, LOW_CONFIDENCE_PATTERNS
from models import Type, Severity, Confidence


def test_aws_access_key():
    code = 'aws_key = "AKIAIOSFODNN7EXAMPLE"'
    findings = detect_secrets(code)

    assert len(findings) == 1
    assert findings[0].description == "AWS Access Key ID"
    assert findings[0].confidence == Confidence.HIGH
    assert "AKIA" in findings[0].snippet


def test_github_token():
    code = 'token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"'
    findings = detect_secrets(code)

    assert len(findings) == 1
    assert findings[0].description == "GitHub Personal Access Token"
    assert "ghp_" in findings[0].snippet


def test_rsa_private_key():
    code = """
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...
-----END RSA PRIVATE KEY-----
"""
    findings = detect_secrets(code)

    assert len(findings) >= 1
    descriptions = [f.description for f in findings]
    assert "RSA private key" in descriptions


def test_stripe_live_key():
    # Split the token so GitHub doesn't recognize it
    prefix = "sk_live_"
    middle = "51ExampleFakeKey"
    suffix = "123456789"
    code = f'STRIPE_KEY = "{prefix}{middle}{suffix}"'
    findings = detect_secrets(code)

    assert len(findings) == 1
    assert findings[0].description == "Stripe Live Secret Key"
    assert "sk_live_" in findings[0].snippet


def test_jwt_token():
    code = 'auth_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"'
    findings = detect_secrets(code)

    assert len(findings) == 1
    assert findings[0].description == "JWT Token"
    assert "eyJ" in findings[0].snippet


def test_database_connection_string():
    code = 'db_url = "postgresql://user:password123@localhost:5432/mydb"'
    findings = detect_secrets(code)

    assert len(findings) == 2
    assert findings[0].description == "Database Connection String"
    assert "postgresql://" in findings[0].snippet
    assert findings[1].description == "Password in URL"
    assert findings[1].confidence == Confidence.LOW


def test_slack_token():
    # Split the token so GitHub doesn't recognize it
    prefix = "xoxb-123456789012"
    middle = "-1234567890123"
    suffix = "-abcdefghijklmnopqrstuvwx"
    code = f'slack = "{prefix}{middle}{suffix}"'
    findings = detect_secrets(code)

    assert len(findings) == 1
    assert findings[0].description == "Slack Token"
    assert "xoxb-" in findings[0].snippet


def test_generic_api_key_low_confidence():
    code = 'api_key = "abcdef1234567890abcdef1234567890abcd"'
    findings = detect_secrets(code)

    assert len(findings) == 1
    assert findings[0].description == "Generic API Key"
    assert findings[0].confidence == Confidence.LOW


def test_password_in_url_low_confidence():
    code = 'url = "https://user:mypassword@example.com/api"'
    findings = detect_secrets(code)

    assert len(findings) == 1
    assert findings[0].description == "Password in URL"
    assert findings[0].confidence == Confidence.LOW


def test_multiple_secrets_same_line():
    code = 'keys = "AKIAIOSFODNN7EXAMPLE and ghp_abcdefghijklmnopqrstuvwxyz123456"'
    findings = detect_secrets(code)

    # Should detect at least the AWS key (only first match per pattern)
    assert len(findings) >= 1


def test_multiple_secrets_different_lines():
    code = """
aws_key = "AKIAIOSFODNN7EXAMPLE"
github_token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
stripe_key = "sk_test_FakeTestKeyForUnitTests123456"
"""
    findings = detect_secrets(code)

    assert len(findings) == 3
    descriptions = [f.description for f in findings]
    assert "AWS Access Key ID" in descriptions
    assert "GitHub Personal Access Token" in descriptions
    # Will match either Stripe Live or Test key pattern
    assert any("Stripe" in d for d in descriptions)


def test_line_numbers_correct():
    code = """line 1
line 2 with AKIAIOSFODNN7EXAMPLE
line 3"""
    findings = detect_secrets(code)

    assert len(findings) == 1
    assert findings[0].line == 2


def test_no_secrets():
    code = """
def hello_world():
    print("Hello, world!")
    return 42
"""
    findings = detect_secrets(code)

    assert len(findings) == 0


def test_false_positive_avoidance():
    # These should NOT trigger (common false positives)
    code = """
# Example AWS key format: AKIA...
password = "test"  # Too short for generic pattern
api_key_placeholder = "YOUR_API_KEY_HERE"
"""
    findings = detect_secrets(code)

    # Should have 0 findings (or verify specific ones you expect)
    assert len(findings) == 0


def test_severity_and_type():
    code = 'key = "AKIAIOSFODNN7EXAMPLE"'
    findings = detect_secrets(code)

    assert findings[0].type == Type.SECRETS
    assert findings[0].severity == Severity.CRITICAL


def test_npm_token():
    code = 'NPM_TOKEN="npm_abcdefghijklmnopqrstuvwxyz123456789"'
    findings = detect_secrets(code)

    assert len(findings) == 1
    assert findings[0].description == "NPM Access Token"


def test_google_api_key():
    code = 'GOOGLE_KEY = "AIzaSyD1234567890abcdefghijklmnopqrstuvwxyz"'
    findings = detect_secrets(code)

    assert len(findings) == 1
    assert findings[0].description == "Google API Key"


def test_pattern_counts():
    """Verify we have the expected number of patterns"""
    assert len(SECRET_PATTERNS) > 20
    assert len(LOW_CONFIDENCE_PATTERNS) > 2