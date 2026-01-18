# ruff: noqa: E501
import argparse
import ast
import json
import re
from dataclasses import dataclass
from pathlib import Path


def normalize_path(path: str) -> str:
    # Replace {param} with {} to compare structure
    return re.sub(r"{[^}]+}", "{}", path)


def extract_path_params(path: str) -> set[str]:
    # Extract parameter names from OpenAPI path: /auth/{referenceNumber} -> {referenceNumber}
    return set(re.findall(r"{([^}]+)}", path))


@dataclass
class EndpointSpec:
    method: str
    path: str
    normalized_path: str
    path_params: set[str]
    query_params: set[str]


@dataclass
class ImplementedEndpoint:
    method: str
    path_pattern: str
    normalized_path: str
    # Parameters detected in the f-string path construction
    detected_path_vars: set[str]
    # Parameters passed to params={} argument
    detected_query_vars: set[str]
    file_path: str
    line_no: int


def get_openapi_specs(openapi_path: Path) -> dict[tuple[str, str], EndpointSpec]:
    """Returns a map of (method, normalized_path) -> EndpointSpec from OpenAPI."""
    with open(openapi_path, encoding="utf-8") as f:
        data = json.load(f)

    specs = {}
    for path, methods in data.get("paths", {}).items():
        norm_path = normalize_path(path)
        path_params = extract_path_params(path)

        for method_name, details in methods.items():
            method = method_name.upper()

            # Extract query parameters defined for this operation
            query_params = set()
            parameters = details.get("parameters", [])
            for param in parameters:
                if param.get("in") == "query":
                    query_params.add(param["name"])

            spec = EndpointSpec(
                method=method,
                path=path,
                normalized_path=norm_path,
                path_params=path_params,
                query_params=query_params,
            )
            specs[(method, norm_path)] = spec
    return specs


class AdvancedClientVisitor(ast.NodeVisitor):
    def __init__(self, filename: str):
        self.filename = filename
        self.found_endpoints: list[ImplementedEndpoint] = []

    def visit_Call(self, node):
        # Look for self._request_json / self._request_bytes / self._request_raw
        if isinstance(node.func, ast.Attribute) and node.func.attr in (
            "_request_json",
            "_request_bytes",
            "_request_no_auth",
            "_request_raw",
        ):
            self._analyze_request_call(node)
        self.generic_visit(node)

    def _analyze_request_call(self, node: ast.Call):
        if len(node.args) < 2:
            return

        method_arg = node.args[0]
        path_arg = node.args[1]

        # Extract Method
        method = self._extract_string_value(method_arg)
        if not method:
            return  # Could not resolve method statically

        # Extract Path and Path Params (from f-strings)
        path_pattern, detected_path_vars = self._extract_path_info(path_arg)
        if not path_pattern:
            return

        normalized_path = normalize_path(path_pattern)

        # Extract Query Params
        detected_query_vars = self._extract_query_params(node)

        self.found_endpoints.append(
            ImplementedEndpoint(
                method=method.upper(),
                path_pattern=path_pattern,
                normalized_path=normalized_path,
                detected_path_vars=detected_path_vars,
                detected_query_vars=detected_query_vars,
                file_path=self.filename,
                line_no=node.lineno,
            )
        )

    def _extract_string_value(self, node) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        return None

    def _extract_path_info(self, node) -> tuple[str | None, set[str]]:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value, set()

        if isinstance(node, ast.JoinedStr):
            # Convert f-string f"/auth/{ref}" to pattern "/auth/{}" and extract vars
            pattern_parts = []
            vars_found = set()

            for part in node.values:
                if isinstance(part, ast.Constant) and isinstance(part.value, str):
                    pattern_parts.append(part.value)
                elif isinstance(part, ast.FormattedValue):
                    pattern_parts.append("{}")
                    # Try to get the variable name used in f-string
                    if isinstance(part.value, ast.Name):
                        vars_found.add(part.value.id)

            return "".join(pattern_parts), vars_found

        return None, set()

    def _extract_query_params(self, node: ast.Call) -> set[str]:
        # Look for 'params' keyword argument
        params_keywords = [kw for kw in node.keywords if kw.arg == "params"]
        if not params_keywords:
            return set()

        params_value = params_keywords[0].value

        # We handle: params={'page': page, 'limit': 10}
        # or params=params (if params is a dict built earlier, hard to track statically perfectly)

        found_keys = set()
        if isinstance(params_value, ast.Dict):
            for key in params_value.keys:
                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                    found_keys.add(key.value)

        # If params passed as variable (e.g. params=page_params), we assume best effort or specific variable name tracking
        # For now, we only statically analyze inline dict definitions or assume manual review if dynamic
        return found_keys


def get_implemented_endpoints_deep(source_dir: Path) -> list[ImplementedEndpoint]:
    endpoints = []
    for py_file in source_dir.rglob("*.py"):
        try:
            visitor = AdvancedClientVisitor(str(py_file))
            tree = ast.parse(py_file.read_text(encoding="utf-8"))
            visitor.visit(tree)
            endpoints.extend(visitor.found_endpoints)
        except Exception as e:
            print(f"Error parsing {py_file}: {e}")
    return endpoints


def to_camel_case(snake_str: str) -> str:
    # reference_number -> referenceNumber
    components = snake_str.split("_")
    return components[0] + "".join(x.title() for x in components[1:])


def main():
    # Re-declare dataclasses here for standalone script execution context if needed
    # (though already defined above, ensuring valid scope)

    parser = argparse.ArgumentParser(description="Deep API coverage check.")
    parser.add_argument("--openapi", required=True, type=Path, help="Path to open-api.json")
    parser.add_argument(
        "--src", required=True, type=Path, help="Path to source directory containing clients"
    )
    args = parser.parse_args()

    # 1. Load OpenAPI Specs
    openapi_specs = get_openapi_specs(args.openapi)

    # 2. Analyze Code
    implemented_eps = get_implemented_endpoints_deep(args.src)

    # 3. Compare
    openapi_keys = set(openapi_specs.keys())
    implemented_keys = set((ep.method, ep.normalized_path) for ep in implemented_eps)

    missing = openapi_keys - implemented_keys
    extra = implemented_keys - openapi_keys

    print(f"OpenAPI Endpoints: {len(openapi_keys)}")
    print(f"Implemented Endpoints: {len(implemented_keys)}")

    issues_found = False

    if missing:
        print("\n[MISSING] The following endpoints are logically missing in code:")
        for method, path in sorted(missing):
            print(f"  - [{method}] {openapi_specs[(method, path)].path}")
        issues_found = True

    if extra:
        print("\n[EXTRA] The following endpoints found in code but NOT in OpenAPI:")
        for method, path in sorted(extra):
            # Try to find file info
            matches = [
                x for x in implemented_eps if x.method == method and x.normalized_path == path
            ]
            for m in matches:
                print(f"  - [{method}] {m.path_pattern} (at {m.file_path}:{m.line_no})")
        # Extra endpoints might be issues if they are typos
        if extra:
            print("   (Note: This might be due to typos in URL or unofficial endpoints)")
            issues_found = True

    # Deep Analysis: Params
    print("\n[DEEP ANALYSIS] Checking Path & Query Parameters...")

    # Map implementation to spec for verification
    for impl in implemented_eps:
        spec = openapi_specs.get((impl.method, impl.normalized_path))
        if not spec:
            continue  # Extra endpoint implemented? or ignored

        # Check Path Params
        # OpenAPI: {referenceNumber} -> Python: reference_number (snake case conversion usually)
        # We try to match count.
        if len(impl.detected_path_vars) != len(spec.path_params):
            # Heuristic check
            print(f"  [WARN] Path param mismatch for {impl.method} {spec.path}")
            print(f"     Expected: {spec.path_params}")
            print(
                f"     Found in f-string: {impl.detected_path_vars} at {impl.file_path}:{impl.line_no}"
            )

        # Check Query Params
        # We only check if the KEY names used in params={} dictionary exist in OpenAPI definition
        # OpenAPI params are usually camelCase (pageSize). Python code should use pageSize key in dict.
        for query_key in impl.detected_query_vars:
            if query_key not in spec.query_params:
                # Common false positive: 'page' vs 'Page', or continuationToken
                print(
                    f"  [WARN] Unknown query param '{query_key}' used in code for {impl.method} {spec.path}"
                )
                print(f"     Allowed: {spec.query_params} at {impl.file_path}:{impl.line_no}")

    if issues_found:
        print("\nCoverage check FAILED.")
        exit(1)
    else:
        print("\nCoverage check PASSED (Structure Match). Review Warnings above.")
        exit(0)


if __name__ == "__main__":
    from dataclasses import dataclass

    main()
