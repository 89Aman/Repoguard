import ast
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from repoguard.core.models import EndpointAuthStatus, EndpointInfo


class ViewDef:
    def __init__(self, name: str, file_path: str):
        self.name = name
        self.file_path = file_path
        self.auth_classes: List[str] = []
        self.permission_classes: List[str] = []
        self.decorators: List[str] = []
        self.is_viewset: bool = False
        self.explicit_methods: List[str] = []


def _extract_string_or_name(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _extract_class_list(node: ast.AST) -> List[str]:
    results = []
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        for elt in node.elts:
            val = _extract_string_or_name(elt)
            if val:
                results.append(val)
    return results


def parse_view_definitions(repo_path: Path) -> Dict[str, ViewDef]:
    views: Dict[str, ViewDef] = {}

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
            if isinstance(node, ast.ClassDef):
                view = ViewDef(node.name, rel_str)
                for base in node.bases:
                    base_name = _extract_string_or_name(base) or ""
                    if "ViewSet" in base_name or "ModelViewSet" in base_name:
                        view.is_viewset = True

                for item in node.body:
                    if isinstance(item, ast.Assign):
                        for target in item.targets:
                            if isinstance(target, ast.Name):
                                if target.id == "permission_classes":
                                    view.permission_classes = _extract_class_list(item.value)
                                elif target.id == "authentication_classes":
                                    view.auth_classes = _extract_class_list(item.value)

                for dec in node.decorator_list:
                    dec_name = _extract_string_or_name(dec)
                    if dec_name:
                        view.decorators.append(dec_name)

                views[node.name] = view

            elif isinstance(node, ast.FunctionDef):
                view = ViewDef(node.name, rel_str)
                for dec in node.decorator_list:
                    if isinstance(dec, ast.Name):
                        view.decorators.append(dec.id)
                    elif isinstance(dec, ast.Call):
                        func_name = _extract_string_or_name(dec.func)
                        if func_name:
                            view.decorators.append(func_name)
                            if func_name == "permission_classes" and dec.args:
                                view.permission_classes = _extract_class_list(dec.args[0])
                            elif func_name == "api_view" and dec.args:
                                view.explicit_methods = _extract_class_list(dec.args[0])

                views[node.name] = view

    return views


def parse_django_urls(repo_path: Path, views: Dict[str, ViewDef], global_allow_any: bool = True) -> List[EndpointInfo]:
    endpoints: List[EndpointInfo] = []

    for url_file in repo_path.rglob("urls.py"):
        rel_str = str(url_file.relative_to(repo_path)).replace("\\", "/")
        if any(ignored in rel_str for ignored in (".venv", "venv", "node_modules")):
            continue

        try:
            with open(url_file, "r", encoding="utf-8", errors="replace") as f:
                code = f.read()
            tree = ast.parse(code, filename=str(url_file))
        except Exception:
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = _extract_string_or_name(node.func) or ""

                if func_name in ("path", "re_path") and len(node.args) >= 2:
                    raw_path = _extract_string_or_name(node.args[0]) or ""
                    clean_path = "/" + raw_path.strip("^$/")
                    if clean_path != "/" and not clean_path.endswith("/"):
                        clean_path += "/"

                    handler_node = node.args[1]
                    handler_name = ""
                    if isinstance(handler_node, ast.Call):
                        if isinstance(handler_node.func, ast.Attribute) and handler_node.func.attr == "as_view":
                            handler_name = _extract_string_or_name(handler_node.func.value) or ""
                    else:
                        handler_name = _extract_string_or_name(handler_node) or ""

                    view_def = views.get(handler_name)
                    auth_classes = view_def.auth_classes if view_def else []
                    perm_classes = view_def.permission_classes if view_def else []
                    decorators = view_def.decorators if view_def else []

                    is_protected = False
                    status = EndpointAuthStatus.UNPROTECTED
                    is_flagged = True
                    notes = "No authentication or permission classes specified"

                    if any("IsAuthenticated" in p or "IsAdminUser" in p for p in perm_classes):
                        is_protected = True
                        status = EndpointAuthStatus.PROTECTED
                        is_flagged = False
                        notes = f"Protected by {', '.join(perm_classes)}"
                    elif "AllowAny" in perm_classes:
                        status = EndpointAuthStatus.UNPROTECTED
                        is_flagged = True
                        notes = "Explicit AllowAny permission applied"
                    elif "login_required" in decorators:
                        is_protected = True
                        status = EndpointAuthStatus.PROTECTED
                        is_flagged = False
                        notes = "Protected by @login_required decorator"
                    elif global_allow_any and not perm_classes:
                        status = EndpointAuthStatus.ALLOW_ANY_DEFAULT
                        is_flagged = True
                        notes = "Unprotected: relies on project global default AllowAny"

                    methods = view_def.explicit_methods if view_def and view_def.explicit_methods else ["GET", "POST"]

                    endpoints.append(
                        EndpointInfo(
                            path=clean_path,
                            http_methods=methods,
                            handler=handler_name or "unknown_view",
                            auth_classes=auth_classes,
                            permission_classes=perm_classes,
                            status=status,
                            is_flagged=is_flagged,
                            notes=notes,
                        )
                    )

                elif func_name == "register" and len(node.args) >= 2:
                    raw_prefix = _extract_string_or_name(node.args[0]) or ""
                    handler_name = _extract_string_or_name(node.args[1]) or ""
                    view_def = views.get(handler_name)
                    perm_classes = view_def.permission_classes if view_def else []
                    auth_classes = view_def.auth_classes if view_def else []

                    is_protected = any("IsAuthenticated" in p or "IsAdminUser" in p for p in perm_classes)
                    status = EndpointAuthStatus.PROTECTED if is_protected else (EndpointAuthStatus.ALLOW_ANY_DEFAULT if global_allow_any else EndpointAuthStatus.UNPROTECTED)

                    base_path = "/" + raw_prefix.strip("/") + "/"
                    detail_path = "/" + raw_prefix.strip("/") + "/{id}/"

                    endpoints.append(
                        EndpointInfo(
                            path=base_path,
                            http_methods=["GET", "POST"],
                            handler=f"{handler_name} (list/create)",
                            auth_classes=auth_classes,
                            permission_classes=perm_classes,
                            status=status,
                            is_flagged=not is_protected,
                            notes="DRF ViewSet collection route" + (" (Unprotected)" if not is_protected else ""),
                        )
                    )
                    endpoints.append(
                        EndpointInfo(
                            path=detail_path,
                            http_methods=["GET", "PUT", "PATCH", "DELETE"],
                            handler=f"{handler_name} (detail)",
                            auth_classes=auth_classes,
                            permission_classes=perm_classes,
                            status=status,
                            is_flagged=not is_protected,
                            notes="DRF ViewSet instance route" + (" (Unprotected)" if not is_protected else ""),
                        )
                    )

    return endpoints
