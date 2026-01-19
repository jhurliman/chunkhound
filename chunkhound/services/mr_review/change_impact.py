"""Analyze backend endpoint changes and map impacted frontend call sites."""

import re
from dataclasses import dataclass
from typing import Iterable

from chunkhound.services.search_service import SearchService


_DIFF_HUNK_RE = re.compile(r"@@ -(?P<old>\d+)(?:,\d+)? \+(?P<new>\d+)(?:,\d+)? @@")
_DIFF_FILE_RE = re.compile(r"^\+\+\+ b/(?P<path>.+)$")
_DIFF_OLD_FILE_RE = re.compile(r"^--- a/(?P<path>.+)$")

_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")

_BACKEND_ROUTE_PATTERNS = [
    # FastAPI / Starlette / APIRouter decorators
    re.compile(
        r"""@(?:router|app)\.(?P<method>get|post|put|patch|delete|head|options)\(
        \s*(?P<quote>['"])(?P<path>[^'"]+)(?P=quote)""",
        re.IGNORECASE | re.VERBOSE,
    ),
    # Flask / Bottle / Falcon style
    re.compile(
        r"""\b(?:app|bp|blueprint)\.(?P<method>get|post|put|patch|delete|head|options)\(
        \s*(?P<quote>['"])(?P<path>[^'"]+)(?P=quote)""",
        re.IGNORECASE | re.VERBOSE,
    ),
    # Express / Koa router
    re.compile(
        r"""\b(?:router|app)\.(?P<method>get|post|put|patch|delete|head|options)\(
        \s*(?P<quote>['"])(?P<path>[^'"]+)(?P=quote)""",
        re.IGNORECASE | re.VERBOSE,
    ),
    # Django path("route", view)
    re.compile(
        r"""\bpath\(\s*(?P<quote>['"])(?P<path>[^'"]+)(?P=quote)""",
        re.IGNORECASE | re.VERBOSE,
    ),
    # Go net/http handlers: http.HandleFunc("/path", ...)
    re.compile(
        r"""\bhttp\.HandleFunc\(\s*(?P<quote>['"])(?P<path>[^'"]+)(?P=quote)""",
        re.IGNORECASE | re.VERBOSE,
    ),
    # Gin router: r.GET("/path", ...)
    re.compile(
        r"""\b\w+\.(?P<method>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\(
        \s*(?P<quote>['"])(?P<path>[^'"]+)(?P=quote)""",
        re.IGNORECASE | re.VERBOSE,
    ),
    # Chi router: r.Method("GET", "/path", ...)
    re.compile(
        r"""\b\w+\.Method\(\s*(?P<quote>['"])(?P<method>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)(?P=quote)
        \s*,\s*(?P<quote2>['"])(?P<path>[^'"]+)(?P=quote2)""",
        re.IGNORECASE | re.VERBOSE,
    ),
    # gRPC proto: rpc Foo(Req) returns (Res);
    re.compile(
        r"""\brpc\s+(?P<rpc>\w+)\s*\(""",
        re.IGNORECASE | re.VERBOSE,
    ),
]

_GRPC_SERVICE_RE = re.compile(r"""\bservice\s+(?P<service>\w+)\s*\{""", re.IGNORECASE)


@dataclass(frozen=True)
class EndpointChange:
    """Represents a backend endpoint change discovered in a diff."""

    method: str | None
    path: str
    change_type: str
    file_path: str | None
    line_number: int | None
    protocol: str = "http"
    grpc_service: str | None = None
    grpc_method: str | None = None


@dataclass(frozen=True)
class CallSite:
    """Represents a frontend call site for an endpoint."""

    path: str
    start_line: int | None
    end_line: int | None
    code_preview: str | None
    in_changed_files: bool


@dataclass(frozen=True)
class EndpointImpact:
    """Mapping between a backend endpoint change and frontend call sites."""

    change: EndpointChange
    call_sites: tuple[CallSite, ...] = ()


@dataclass(frozen=True)
class ImpactReport:
    """Aggregated impact analysis for a merge request diff."""

    endpoint_changes: tuple[EndpointChange, ...]
    impacts: tuple[EndpointImpact, ...]

    @property
    def total_changes(self) -> int:
        return len(self.endpoint_changes)

    @property
    def total_call_sites(self) -> int:
        return sum(len(impact.call_sites) for impact in self.impacts)


@dataclass(frozen=True)
class ImpactAnalysisOptions:
    """Options controlling endpoint impact analysis."""

    frontend_path_filter: str | None = None
    callsite_page_size: int = 20
    include_removed: bool = True


def analyze_endpoint_changes(
    diff_text: str,
    search_service: SearchService,
    changed_files: Iterable[str] | None = None,
    options: ImpactAnalysisOptions | None = None,
) -> ImpactReport:
    """Analyze backend endpoint changes and map impacted frontend call sites.

    Args:
        diff_text: Unified diff text from a merge request.
        search_service: SearchService instance for regex lookups.
        changed_files: Optional iterable of changed file paths in the MR.
        options: Analysis options controlling search behavior.

    Returns:
        ImpactReport containing detected endpoint changes and call sites.
    """
    resolved_options = options or ImpactAnalysisOptions()
    changed_files_set = set(changed_files or [])

    endpoint_changes = _extract_endpoint_changes(diff_text)
    if not resolved_options.include_removed:
        endpoint_changes = [
            change for change in endpoint_changes if change.change_type != "removed"
        ]

    impacts = []
    for change in endpoint_changes:
        call_sites = _find_call_sites(
            change,
            search_service,
            changed_files_set,
            resolved_options,
        )
        impacts.append(EndpointImpact(change=change, call_sites=tuple(call_sites)))

    return ImpactReport(
        endpoint_changes=tuple(endpoint_changes),
        impacts=tuple(impacts),
    )


def _extract_endpoint_changes(diff_text: str) -> list[EndpointChange]:
    current_file = None
    old_line = None
    new_line = None
    grpc_service = None
    changes: list[EndpointChange] = []

    for raw_line in diff_text.splitlines():
        file_match = _DIFF_FILE_RE.match(raw_line)
        if file_match:
            current_file = file_match.group("path")
            continue

        old_file_match = _DIFF_OLD_FILE_RE.match(raw_line)
        if old_file_match and current_file is None:
            current_file = old_file_match.group("path")
            continue

        hunk_match = _DIFF_HUNK_RE.match(raw_line)
        if hunk_match:
            old_line = int(hunk_match.group("old"))
            new_line = int(hunk_match.group("new"))
            continue

        if raw_line.startswith("+") and not raw_line.startswith("+++"):
            content = raw_line[1:]
            grpc_service = _update_grpc_service(content, grpc_service)
            changes.extend(
                _extract_changes_from_line(
                    content,
                    "added",
                    current_file,
                    new_line,
                    grpc_service,
                )
            )
            if new_line is not None:
                new_line += 1
            continue

        if raw_line.startswith("-") and not raw_line.startswith("---"):
            content = raw_line[1:]
            grpc_service = _update_grpc_service(content, grpc_service)
            changes.extend(
                _extract_changes_from_line(
                    content,
                    "removed",
                    current_file,
                    old_line,
                    grpc_service,
                )
            )
            if old_line is not None:
                old_line += 1
            continue

        if raw_line.startswith(" "):
            grpc_service = _update_grpc_service(raw_line[1:], grpc_service)
            if old_line is not None:
                old_line += 1
            if new_line is not None:
                new_line += 1

    return changes


def _extract_changes_from_line(
    content: str,
    change_type: str,
    file_path: str | None,
    line_number: int | None,
    grpc_service: str | None,
) -> list[EndpointChange]:
    changes: list[EndpointChange] = []
    for pattern in _BACKEND_ROUTE_PATTERNS:
        match = pattern.search(content)
        if not match:
            continue

        if match.groupdict().get("rpc"):
            rpc_name = match.group("rpc")
            grpc_path = _format_grpc_path(grpc_service, rpc_name)
            changes.append(
                EndpointChange(
                    method=None,
                    path=grpc_path,
                    change_type=change_type,
                    file_path=file_path,
                    line_number=line_number,
                    protocol="grpc",
                    grpc_service=grpc_service,
                    grpc_method=rpc_name,
                )
            )
            continue

        method = match.groupdict().get("method")
        if method:
            method = method.lower()
            if method not in _METHODS:
                method = None

        path = match.groupdict().get("path")
        if not path:
            continue

        changes.append(
            EndpointChange(
                method=method,
                path=path,
                change_type=change_type,
                file_path=file_path,
                line_number=line_number,
            )
        )

    return changes


def _find_call_sites(
    change: EndpointChange,
    search_service: SearchService,
    changed_files_set: set[str],
    options: ImpactAnalysisOptions,
) -> list[CallSite]:
    regex_pattern = _build_callsite_regex(change)
    results, _ = search_service.search_regex(
        pattern=regex_pattern,
        page_size=options.callsite_page_size,
        offset=0,
        path_filter=options.frontend_path_filter,
    )

    call_sites = []
    for result in results:
        path = result.get("path")
        call_sites.append(
            CallSite(
                path=path,
                start_line=result.get("start_line"),
                end_line=result.get("end_line"),
                code_preview=result.get("code_preview"),
                in_changed_files=path in changed_files_set if path else False,
            )
        )
    return call_sites


def _build_callsite_regex(change: EndpointChange) -> str:
    if change.protocol == "grpc":
        return _build_grpc_callsite_regex(change)

    normalized = change.path.strip()
    if not normalized.startswith("/"):
        normalized = f"/{normalized}"

    escaped = re.escape(normalized)
    escaped = re.sub(r"\\:\\w+", r"[^/]+", escaped)
    escaped = re.sub(r"\\{[^}]+\\}", r"[^/]+", escaped)
    escaped = re.sub(r"\\<[^>]+\\>", r"[^/]+", escaped)
    escaped = escaped.replace("\\*", ".*")

    axios_pattern = rf"axios\.(?:{_METHODS_PATTERN})\(\s*{_wrap_quotes(escaped)}"
    axios_config_pattern = rf"axios\(\s*\{{[^}}]*{_wrap_quotes(escaped)}"
    return rf"(?:{escaped}|{axios_pattern}|{axios_config_pattern})"


def _build_grpc_callsite_regex(change: EndpointChange) -> str:
    if change.grpc_service and change.grpc_method:
        grpc_target = re.escape(f"{change.grpc_service}/{change.grpc_method}")
        return rf"(?:{grpc_target}|{re.escape(change.grpc_method)})"

    return re.escape(change.path)


def _update_grpc_service(content: str, current_service: str | None) -> str | None:
    service_match = _GRPC_SERVICE_RE.search(content)
    if not service_match:
        return current_service
    return service_match.group("service")


def _format_grpc_path(service: str | None, rpc_name: str) -> str:
    if service:
        return f"{service}/{rpc_name}"
    return rpc_name


def _wrap_quotes(pattern: str) -> str:
    return rf"(?:['\"]){pattern}(?:['\"])"


_METHODS_PATTERN = "|".join(_METHODS)
