import ast
from models import Finding, Type, Severity, Confidence
from sast.rules import SQL_EXECUTION_METHODS


class SQLiDetector(ast.NodeVisitor):
    def __init__(self):
        self.findings = []

    def visit_Call(self, node):
        # Check if calling db.execute or cursor.execute
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in SQL_EXECUTION_METHODS:
                # Check if first argument uses string formatting or concatenation
                if node.args and self._is_unsafe_query(node.args[0]):
                    self.findings.append(Finding(
                        type=Type.SQL_INJECTION,
                        line=node.lineno,
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH
                    ))
        self.generic_visit(node)

    def _is_unsafe_query(self, node: ast.expr) -> bool:
        # Detect dangerous string composition patterns:
        # - ast.JoinedStr: f-strings like f"SELECT * FROM users WHERE id={uid}"
        # - ast.BinOp: concatenation like "SELECT * FROM users WHERE id=" + uid
        # Both allow user input to be interpreted as SQL code
        # TODO::  Add basic data flow tracking
        if isinstance(node, ast.JoinedStr):  # f-strings
            return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):  # string concatenation
            return True
        if isinstance(node, ast.Call):  # .format() or % formatting
            if isinstance(node.func, ast.Attribute) and node.func.attr == 'format':
                return True
        return False