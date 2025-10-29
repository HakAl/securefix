from typing import Dict, Any
from models import Type, Severity, Confidence, Finding

# This dictionary maps the Bandit 'test_id'
BANDIT_ID_TO_TYPE = {
    # Hardcoded Secrets
    "B105": Type.SECRETS,  # hardcoded_password_string
    "B106": Type.SECRETS,  # hardcoded_password_funcarg
    "B107": Type.SECRETS,  # hardcoded_password_default
    "B104": Type.SECRETS,  # hardcoded_bind_all_interfaces

    # SQL Injection
    "B608": Type.SQL_INJECTION,  # hardcoded_sql_expressions
    "B610": Type.SQL_INJECTION,  # django_extra_used
    "B611": Type.SQL_INJECTION,  # django_rawsql_used

    # Command Injection
    "B602": Type.COMMAND_INJECTION,  # subprocess_popen_with_shell_equals_true
    "B603": Type.COMMAND_INJECTION,  # subprocess_without_shell_equals_true
    "B604": Type.COMMAND_INJECTION,  # any_other_function_with_shell_equals_true
    "B605": Type.COMMAND_INJECTION,  # start_process_with_a_shell
    "B606": Type.COMMAND_INJECTION,  # start_process_with_no_shell
    "B607": Type.COMMAND_INJECTION,  # start_process_with_partial_path
    "B609": Type.COMMAND_INJECTION,  # linux_commands_wildcard_injection

    # Insecure Deserialization
    "B301": Type.INSECURE_DESERIALIZATION,  # pickle
    "B302": Type.INSECURE_DESERIALIZATION,  # marshal
    "B506": Type.INSECURE_DESERIALIZATION,  # yaml_load
    "B614": Type.INSECURE_DESERIALIZATION,  # pytorch_load

    # Insecure Temp Files & Path Traversal
    "B108": Type.INSECURE_TEMP_FILE,  # hardcoded_tmp_directory
    "B202": Type.PATH_TRAVERSAL,  # tarfile_unsafe_members

    # XML Vulnerabilities
    "B313": Type.XML_VULNERABILITY,  # xml_bad_cElementTree
    "B314": Type.XML_VULNERABILITY,  # xml_bad_ElementTree
    "B315": Type.XML_VULNERABILITY,  # xml_bad_expatreader
    "B316": Type.XML_VULNERABILITY,  # xml_bad_expatbuilder
    "B317": Type.XML_VULNERABILITY,  # xml_bad_sax
    "B318": Type.XML_VULNERABILITY,  # xml_bad_minidom
    "B319": Type.XML_VULNERABILITY,  # xml_bad_pulldom
    "B320": Type.XML_VULNERABILITY,  # xml_bad_etree

    # Weak Cryptography
    "B324": Type.CRYPTO_WEAKNESS,  # hashlib_insecure_functions (MD5, SHA1)
    "B501": Type.CRYPTO_WEAKNESS,  # request_with_no_cert_validation
    "B502": Type.CRYPTO_WEAKNESS,  # ssl_with_bad_version
    "B503": Type.CRYPTO_WEAKNESS,  # ssl_with_bad_defaults
    "B504": Type.CRYPTO_WEAKNESS,  # ssl_with_no_version
    "B505": Type.CRYPTO_WEAKNESS,  # weak_cryptographic_key
    "B507": Type.CRYPTO_WEAKNESS,  # ssh_no_host_key_verification
    "B508": Type.CRYPTO_WEAKNESS,  # snmp_insecure_version
    "B509": Type.CRYPTO_WEAKNESS,  # snmp_weak_cryptography

    # Cross-Site Scripting (XSS)
    "B701": Type.XSS,  # jinja2_autoescape_false
    "B702": Type.XSS,  # use_of_mako_templates
    "B703": Type.XSS,  # django_mark_safe
    "B704": Type.XSS,  # markupsafe_markup_xss

    # Dangerous Code Execution
    "B101": Type.DANGEROUS_CODE,  # assert_used
    "B102": Type.DANGEROUS_CODE,  # exec_used
    "B103": Type.DANGEROUS_CODE,  # set_bad_file_permissions

    # Insecure Configuration
    "B201": Type.INSECURE_CONFIG,  # flask_debug_true
    "B612": Type.INSECURE_CONFIG,  # logging_config_insecure_listen
    "B113": Type.INSECURE_CONFIG,  # request_without_timeout
    "B601": Type.INSECURE_CONFIG,  # paramiko_calls

    # Security Vulnerabilities (misc)
    "B110": Type.DANGEROUS_CODE,  # try_except_pass
    "B112": Type.DANGEROUS_CODE,  # try_except_continue
    "B613": Type.DANGEROUS_CODE,  # trojansource
    "B615": Type.INSECURE_DESERIALIZATION,  # huggingface_unsafe_download
}


def convert_bandit_result(result: Dict[str, Any]) -> Finding:
    """Maps a single Bandit result dictionary to your internal Finding model."""

    bandit_id = result.get("test_id")
    finding_type = BANDIT_ID_TO_TYPE.get(bandit_id, Type.UNKNOWN)

    # Map Bandit's lowercase severity/confidence to your enums
    severity_str = result.get("issue_severity", "low").lower()
    confidence_str = result.get("issue_confidence", "low").lower()

    # Clean up snippet - remove line numbers
    raw_code = result.get("code", "")
    if raw_code:
        import re
        lines = raw_code.split('\n')
        cleaned_lines = []
        for line in lines:
            # Remove leading line number (e.g., "45         code" -> "code")
            cleaned = re.sub(r'^\d+\s*', '', line)
            cleaned_lines.append(cleaned)  # Keep ALL lines, even if empty after cleaning
        snippet = '\n'.join(cleaned_lines).strip()  # Strip only at the end
    else:
        snippet = None

    return Finding(
        type=finding_type,
        line=result.get("line_number"),
        severity=Severity[severity_str.upper()],
        confidence=Confidence[confidence_str.upper()],
        snippet=snippet,
        description=result.get("issue_text"),
        file=result.get("filename"),
    )