import ast
from sast.detectors.sql_injection import SQLiDetector
from models import Type, Severity, Confidence


def test_detects_f_string_injection():
    """Should detect SQL injection using f-strings"""
    code = """
def get_user(uid):
    cursor.execute(f"SELECT * FROM users WHERE id={uid}")
"""
    tree = ast.parse(code)
    detector = SQLiDetector()
    detector.visit(tree)

    assert len(detector.findings) == 1
    assert detector.findings[0].type == Type.SQL_INJECTION
    assert detector.findings[0].severity == Severity.HIGH
    assert detector.findings[0].confidence == Confidence.HIGH


def test_detects_string_concatenation():
    """Should detect SQL injection using + concatenation"""
    code = """
def get_user(name):
    cursor.execute("SELECT * FROM users WHERE name=" + name)
"""
    tree = ast.parse(code)
    detector = SQLiDetector()
    detector.visit(tree)

    assert len(detector.findings) == 1
    assert detector.findings[0].type == Type.SQL_INJECTION


def test_detects_format_method():
    """Should detect SQL injection using .format()"""
    code = """
def get_user(uid):
    cursor.execute("SELECT * FROM users WHERE id={}".format(uid))
"""
    tree = ast.parse(code)
    detector = SQLiDetector()
    detector.visit(tree)

    assert len(detector.findings) == 1


def test_no_false_positive_on_parameterized_query():
    """Should NOT flag safe parameterized queries"""
    code = """
def get_user(uid):
    cursor.execute("SELECT * FROM users WHERE id=%s", (uid,))
"""
    tree = ast.parse(code)
    detector = SQLiDetector()
    detector.visit(tree)

    assert len(detector.findings) == 0


def test_no_false_positive_on_static_query():
    """Should NOT flag queries with no user input"""
    code = """
def get_all_users():
    cursor.execute("SELECT * FROM users")
"""
    tree = ast.parse(code)
    detector = SQLiDetector()
    detector.visit(tree)

    assert len(detector.findings) == 0


def test_detects_read_sql_injection():
    """Should detect SQL injection in pandas read_sql"""
    code = """
def get_data(table):
    df = pd.read_sql(f"SELECT * FROM {table}", conn)
"""
    tree = ast.parse(code)
    detector = SQLiDetector()
    detector.visit(tree)

    assert len(detector.findings) == 1