# SPDX-License-Identifier: MIT
"""The server, the in-memory model and the fault injection.

The model mirrors what the real API does where safo has been bitten: a listing that lags behind
`items.totalCount` after an add, a `createProjectV2View` that accepts no filter, a field update that
wipes values, a repository the installation does not cover answering NOT_FOUND.
"""

from __future__ import annotations

import json
import re
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

JSON = dict[str, Any]
Handler = Callable[["FakeGitHub", JSON], JSON]
HANDLERS: dict[str, Handler] = {}
_OPERATION = re.compile(r"^\s*(query|mutation)\s+(\w+)")


def handler(name: str) -> Callable[[Handler], Handler]:
    def register(fn: Handler) -> Handler:
        HANDLERS[name] = fn
        return fn

    return register


class GqlError(Exception):
    def __init__(self, kind: str, message: str, data: JSON | None = None) -> None:
        super().__init__(message)
        self.kind = kind
        self.data = data


@dataclass
class Mutation:
    op: str
    variables: JSON


@dataclass
class Fault:
    """Answer the next `times` matching requests with this HTTP response instead of processing them."""

    status: int
    headers: dict[str, str] = field(default_factory=dict)
    body: str = "{}"
    times: int = 1
    op: str | None = None  # only requests for this operation
    after: int = 0  # let this many matching requests through first
    commit_then_drop: bool = False  # if true, process the request (record mutation) then drop connection


@dataclass
class FOption:
    id: str
    name: str
    color: str = "GRAY"
    description: str = ""


@dataclass
class FField:
    id: str
    name: str
    data_type: str
    options: list[FOption] = field(default_factory=list)
    iterations: list[JSON] = field(default_factory=list)
    duration: int = 14


@dataclass
class FView:
    id: str
    name: str
    layout: str
    filter: str = ""


@dataclass
class FContent:
    id: str
    kind: str  # Issue | PullRequest
    number: int
    repo: str
    title: str = ""
    state: str = "OPEN"  # OPEN | CLOSED | MERGED
    closed_at: str | None = None
    draft: bool = False
    labels: list[str] = field(default_factory=list)


@dataclass
class FItem:
    id: str
    content_id: str | None
    values: JSON = field(default_factory=dict)  # field id -> option id | date | text
    hidden_for: int = 0  # listings that still leave this item out (a fresh add can lag)


@dataclass
class FProject:
    id: str
    number: int
    title: str
    owner_type: str
    owner: str
    fields: list[FField] = field(default_factory=list)
    views: list[FView] = field(default_factory=list)
    items: list[FItem] = field(default_factory=list)


@dataclass
class FRepo:
    full_name: str
    installed: bool = True
    contents: list[FContent] = field(default_factory=list)


class FakeGitHub:
    def __init__(self, token: str = "test-token", page_size: int = 100) -> None:
        self.token = token
        self.page_size = page_size
        self.projects: dict[str, FProject] = {}
        self.owners: dict[tuple[str, str], str] = {}  # (owner_type, login) -> node id
        self.repos: dict[str, FRepo] = {}
        self.mutations: list[Mutation] = []
        self.requests: list[str] = []
        self.faults: list[Fault] = []
        self.listing_lag = 0
        self.vanished: set[str] = set()  # item ids that answer NOT_FOUND to any edit
        self.handlers: dict[str, Handler] = {}  # per-test overrides of the registered handlers
        self._seq = 0
        self._url = ""

    # -- building the world ----------------------------------------------------------

    def new_id(self, prefix: str) -> str:
        self._seq += 1
        return f"{prefix}_{self._seq:04d}"

    def add_owner(self, owner_type: str, login: str) -> str:
        self.owners[(owner_type, login)] = self.new_id("OWNER")
        return self.owners[(owner_type, login)]

    def add_project(self, owner_type: str, owner: str, number: int, title: str, *, builtin: bool = True) -> FProject:
        if (owner_type, owner) not in self.owners:
            self.add_owner(owner_type, owner)
        project = FProject(self.new_id("PVT"), number, title, owner_type, owner)
        if builtin:
            for name in ("Title", "Assignees", "Labels"):
                project.fields.append(
                    FField(
                        self.new_id("PVTF"),
                        name,
                        "TITLE" if name == "Title" else "ASSIGNEES" if name == "Assignees" else "LABELS",
                    )
                )
        self.projects[project.id] = project
        return project

    def add_field(
        self, project: FProject, name: str, data_type: str, options: list[tuple[str, str, str]] | None = None
    ) -> FField:
        f = FField(self.new_id("PVTSSF" if data_type == "SINGLE_SELECT" else "PVTF"), name, data_type)
        for opt_name, color, description in options or []:
            f.options.append(FOption(self.new_id("OPT"), opt_name, color, description))
        project.fields.append(f)
        return f

    def add_view(self, project: FProject, name: str, layout: str, filter: str = "") -> FView:
        v = FView(self.new_id("PVTV"), name, layout, filter)
        project.views.append(v)
        return v

    def add_repo(self, full_name: str, *, installed: bool = True) -> FRepo:
        repo = FRepo(full_name, installed)
        self.repos[full_name.lower()] = repo
        return repo

    def add_content(self, repo: str, kind: str, number: int, title: str = "", **kw: Any) -> FContent:
        c = FContent(
            self.new_id("ISSUE" if kind == "Issue" else "PR"), kind, number, repo, title or f"{kind} {number}", **kw
        )
        self.repos[repo.lower()].contents.append(c)
        return c

    def content(self, content_id: str) -> FContent | None:
        return next((c for r in self.repos.values() for c in r.contents if c.id == content_id), None)

    def add_item(self, project: FProject, content: FContent | None, **values: str) -> FItem:
        item = FItem(self.new_id("PVTI"), content.id if content else None)
        for name, value in values.items():
            f = self.field(project, name.replace("_", " "))
            item.values[f.id] = next((o.id for o in f.options if o.name == value), value) if f.options else value
        project.items.append(item)
        return item

    def field(self, project: FProject, name: str) -> FField:
        return next(f for f in project.fields if f.name == name)

    def value(self, project: FProject, item: FItem, field_name: str) -> str | None:
        """The option name or date an item holds for a field, or None."""
        f = self.field(project, field_name)
        raw = item.values.get(f.id)
        if raw is None:
            return None
        return next((o.name for o in f.options if o.id == raw), str(raw))

    def project_by_number(self, owner_type: str, owner: str, number: int) -> FProject | None:
        return next(
            (p for p in self.projects.values() if (p.owner_type, p.owner, p.number) == (owner_type, owner, number)),
            None,
        )

    def mutations_named(self, *ops: str) -> list[Mutation]:
        return [m for m in self.mutations if m.op in ops]

    # -- pagination -------------------------------------------------------------------

    def connection(self, nodes: list[Any], variables: JSON, total: int | None = None) -> JSON:
        start = int(variables.get("endCursor") or 0)
        end = min(start + self.page_size, len(nodes))
        out: JSON = {"pageInfo": {"hasNextPage": end < len(nodes), "endCursor": str(end)}, "nodes": nodes[start:end]}
        if total is not None:
            out["totalCount"] = total
        return out

    # -- serving -------------------------------------------------------------------------

    @property
    def url(self) -> str:
        return self._url

    @contextmanager
    def serve(self) -> Iterator[FakeGitHub]:
        fake = self

        class Request(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(length) or b"{}")
                status, headers, payload, drop_connection = fake.respond(body, self.headers.get("Authorization"))
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                for key, value in headers.items():
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                if drop_connection:
                    # Abruptly close the connection without sending the body, simulating a timeout/reset
                    self.connection.close()
                else:
                    self.wfile.write(payload)

            def log_message(self, format: str, *args: Any) -> None:
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Request)
        self._url = f"http://127.0.0.1:{server.server_address[1]}/graphql"
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        try:
            yield self
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def respond(self, body: JSON, auth: str | None) -> tuple[int, dict[str, str], bytes, bool]:
        """Return (status, headers, payload, should_drop_connection)."""
        document = str(body.get("query", ""))
        match = _OPERATION.match(document)
        op = str(body.get("operationName") or "")
        if not match or match.group(2) != op:
            return 400, {}, b'{"message": "operationName does not match the document"}', False
        if auth != f"Bearer {self.token}":
            return 401, {}, b'{"message": "Bad credentials"}', False
        fault = self._next_fault(op)
        self.requests.append(op)
        variables: JSON = body.get("variables") or {}

        # If commit_then_drop, process the mutation first
        if fault and fault.commit_then_drop:
            if match.group(1) == "mutation":
                self.mutations.append(Mutation(op, variables))
            return fault.status, fault.headers, fault.body.encode(), True

        # Normal fault handling (return immediately without processing)
        if fault:
            return fault.status, fault.headers, fault.body.encode(), False

        # Normal request processing
        if match.group(1) == "mutation":
            self.mutations.append(Mutation(op, variables))
        fn = self.handlers.get(op) or HANDLERS.get(op)
        if fn is None:
            return (
                200,
                {},
                json.dumps({"errors": [{"type": "INTERNAL", "message": f"fake has no handler for {op}"}]}).encode(),
                False,
            )
        try:
            data = fn(self, variables | {"__document__": document})
        except GqlError as err:
            error = {"type": err.kind, "message": str(err)}
            return 200, {}, json.dumps({"data": err.data, "errors": [error]}).encode(), False
        return 200, {}, json.dumps({"data": data}).encode(), False

    def _next_fault(self, op: str) -> Fault | None:
        for fault in self.faults:
            if fault.op not in (None, op):
                continue
            if fault.after > 0:
                fault.after -= 1
                return None
            fault.times -= 1
            if fault.times <= 0:
                self.faults.remove(fault)
            return fault
        return None
