import ast
from pathlib import Path
from typing import List, Optional
from repoguard.core.models import EndpointAuthStatus, EndpointInfo


def _extract_string_or_name(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def parse_flask_routes(repo_path: Path) -> List[EndpointInfo]:
    endpoints: List[EndpointInfo] = []

    for py_file in repo_path.rglob("*.py"):
        rel_str = str(py_file.relative_to(repo_path)).replace("\\", "/")
        if any(ignored in rel_str for ignored in (".venv", "venv", "node_modules")):
            continue

        try:
            with open(py_file, "r", encoding="utf-8", errors="replace") as f:
                code = f.read()
            tree = ast.parse(code, filename=str(py_file))
        except Exception:
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                for dec in node.decorator_list:
                    if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute):
                        if dec.func.attr == "route" and dec.args:
                            raw_path = _extract_string_or_name(dec.args[0]) or "/"
                            clean_path = "/" + raw_path.strip("/")
                            if clean_path != "/" and not clean_path.endswith("/"):
                                clean_path += "/"

                            methods = ["GET"]
                            for kw in dec.keywords:
                                if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple, ast.Set)):
                                    extracted = []
                                    for elt in kw.value.elts:
                                        m = _extract_string_or_name(elt)
                                        if m:
                                            extracted.append(m.upper())
                                    if extracted:
                                        methods = extracted

                            decorator_names = []
                            for d in node.decorator_list:
                                if isinstance(d, ast.Name):
                                    decorator_names.append(d.id)
                                elif isinstance(d, ast.Call):
                                    name = _extract_string_or_name(d.func)
                                    if name:
                                        decorator_names.append(name)

                            is_protected = any(auth in decorator_names for auth in ("login_required", "jwt_required", "auth_required", "fresh_jwt_required"))
                            status = EndpointAuthStatus.PROTECTED if is_protected else EndpointAuthStatus.UNPROTECTED
                            is_flagged = not is_protected
                            notes = "Protected by auth decorator" if is_protected else "No authentication decorator applied"

                            endpoints.append(
                                EndpointInfo(
                                    path=clean_path,
                                    http_methods=methods,
                                    handler=f"{node.name} ({rel_str})",
                                    auth_classes=decorator_names,
                                    permission_classes=[],
                                    status=status,
                                    is_flagged=is_flagged,
                                    notes=notes,
                                )
                            )

    return endpoints
