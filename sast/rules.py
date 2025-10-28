SQL_EXECUTION_METHODS = ['execute', 'executemany', 'executescript', 'read_sql', 'read_sql_query']

SECRET_PATTERNS = {
    # Private Keys
    "RSA private key": r"-----BEGIN RSA PRIVATE KEY-----",
    "SSH (DSA) private key": r"-----BEGIN DSA PRIVATE KEY-----",
    "SSH (EC) private key": r"-----BEGIN EC PRIVATE KEY-----",
    "SSH (OPENSSH) private key": r"-----BEGIN OPENSSH PRIVATE KEY-----",
    "PGP private key block": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",

    # AWS
    "AWS Access Key ID": r"\bAKIA[0-9A-Z]{16}\b",
    "AWS Secret Access Key": r"(?i)aws[_-]?secret[_-]?access[_-]?key['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9/+=]{40}['\"]?",
    "AWS Session Token": r"\b(?:A3T|ASIA)[0-9A-Z]{16,}\b",
    "Amazon MWS Auth Token": r"\bamzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",

    # GitHub
    "GitHub Personal Access Token": r"\bgh[ps]_[a-zA-Z0-9]{36,}\b",
    "GitHub OAuth Token": r"\bgho_[a-zA-Z0-9]{36,}\b",
    "GitHub App Token": r"\bghu_[a-zA-Z0-9]{36,}\b",
    "GitHub Refresh Token": r"\bghr_[a-zA-Z0-9]{36,}\b",
    "GitHub Legacy Token": r"(?i)(?:github|gh)[_-]?(?:token|key|secret)['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9]{35,40}['\"]?",

    # Google / GCP
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Google Cloud Platform OAuth": r"\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b",
    "Google OAuth Access Token": r"\bya29\.[0-9A-Za-z\-_]+\b",
    "GCP Service Account Key": r'"type"\s*:\s*"service_account"',

    # Tokens
    "JWT Token": r"\beyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*\b",

    # Slack
    "Slack Token": r"\bxox[baprs]-[0-9a-zA-Z]{10,72}\b",
    "Slack Webhook": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",

    # Stripe
    "Stripe Live Secret Key": r"\bsk_live_[0-9a-zA-Z]{24,}\b",
    "Stripe Live Publishable Key": r"\bpk_live_[0-9a-zA-Z]{24,}\b",
    "Stripe Test Secret Key": r"\bsk_test_[0-9a-zA-Z]{24,}\b",
    "Stripe Restricted Key": r"\brk_live_[0-9a-zA-Z]{24,}\b",

    # Twitter / X
    "Twitter Access Token": r"\b[0-9]{15,}-[a-zA-Z0-9]{20,}\b",
    "Twitter OAuth": r"(?i)twitter[_-]?(?:oauth|token|key)['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9]{35,44}['\"]?",

    # NPM
    "NPM Access Token": r"npm_[a-zA-Z0-9]{32,}",

    # Azure
    "Azure Storage Account Key": r"(?i)(?:azure|storage)[_-]?(?:account|key)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9+/]{86}==)['\"]?",
    "Azure Client Secret": r"(?i)client[_-]?secret['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9\-_.~]{34,40})['\"]?",

    # Database Connection Strings
    "Database Connection String": r"(?i)(mongodb|mysql|postgres|postgresql|mssql|oracle)://[^\s:@]+:[^\s:@]+@[^\s]+"
}

LOW_CONFIDENCE_PATTERNS = {
    # Generic Patterns (use cautiously - high false positive rate)
    "Generic API Key": r"(?i)\b(?:api[_-]?key|apikey)['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9\-_]{32,})['\"]",
    "Generic Secret": r"(?i)\b(?:secret|password|passwd|pwd)['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9\-_!@#$%^&*()]{16,})['\"]",
    "Password in URL": r"(?i)[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]{3,20}:[^/\s:@]{3,20}@[^\s]+",

    # Private Keys in environment variables or config
    "Private Key in Config": r"(?i)(?:private[_-]?key|privatekey)['\"]?\s*[:=]\s*['\"]([^'\"]+)['\"]"
}