import ast
import sys

def remove_docstrings(source: str) -> str:
    """Remove all docstrings from Python source code."""
    tree = ast.parse(source)
    lines = source.splitlines(keepends=True)

    # Collect line ranges to remove (1-indexed from ast)
    ranges_to_remove = []

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Module)):
            if (node.body and isinstance(node.body[0], ast.Expr)
                    and isinstance(node.body[0].value, (ast.Constant, ast.Str))):
                doc_node = node.body[0]
                ranges_to_remove.append((doc_node.lineno - 1, doc_node.end_lineno))

    # Remove lines in reverse order to preserve indices
    for start, end in sorted(ranges_to_remove, reverse=True):
        del lines[start:end]

    return ''.join(lines)

if __name__ == "__main__":
    filepath = sys.argv[1]
    with open(filepath, 'r') as f:
        source = f.read()
    result = remove_docstrings(source)
    with open(filepath, 'w') as f:
        f.write(result)
    print(f"Docstrings removed from {filepath}")