# SPDX-License-Identifier: MIT
"""The client against the fake: retries, rate limits, pagination, dry run, and what it must never send."""

from __future__ import annotations

import io

import pytest

from fakegh import FakeGitHub, GqlError
from fakegh.core import Fault
from safo.errors import ApiError, AuthError, ConfigError, RateLimitedError, SafoError
from safo.graphql import Client, is_mutation, operation_name

FIELDS = """query ProjectFieldsOrg($login: String!, $number: Int!, $endCursor: String) {
  organization(login: $login) { projectV2(number: $number) {
    fields(first: 100, after: $endCursor) { pageInfo { hasNextPage endCursor } nodes { id name } }
  } }
}"""
META = """query ProjectMetaOrg($login: String!, $number: Int!) {
  organization(login: $login) { projectV2(number: $number) { id title number items { totalCount } } }
}"""
VARS = {"login": "acme", "number": 1}


def world(fake: FakeGitHub, extra_fields: int = 0) -> None:
    project = fake.add_project("organization", "acme", 1, "Board")
    for i in range(extra_fields):
        fake.add_field(project, f"Extra {i}", "TEXT")


def test_operation_names_are_read_from_the_document() -> None:
    assert operation_name(META) == "ProjectMetaOrg"
    assert not is_mutation(META)
    assert is_mutation("mutation Add($x: ID!) { a }")
    with pytest.raises(SafoError):
        operation_name("{ viewer { login } }")


def test_a_query_carries_the_operation_name_and_a_bearer_token(fake: FakeGitHub, client: Client) -> None:
    world(fake)
    data = client.execute(META, VARS)
    assert data["organization"]["projectV2"]["title"] == "Board"
    assert fake.requests == ["ProjectMetaOrg"]


def test_a_401_is_an_auth_error_that_never_prints_the_token(fake: FakeGitHub) -> None:
    bad = Client("ghp_SECRETSECRETSECRET", fake.url, sleep=lambda s: None)
    with pytest.raises(AuthError) as err:
        bad.execute(META, VARS)
    assert "ghp_SECRETSECRETSECRET" not in str(err.value)
    assert "ghp_SECRETSECRETSECRET" not in repr(bad)


def test_a_secondary_rate_limit_with_retry_after_waits_that_long_and_retries(
    fake: FakeGitHub, client: Client, sleeps: list[float]
) -> None:
    world(fake)
    fake.faults.append(Fault(403, {"Retry-After": "7"}, '{"message": "secondary rate limit"}', times=2))
    assert client.execute(META, VARS)["organization"]["projectV2"]["number"] == 1
    assert sleeps == [7.0, 7.0]


def test_a_secondary_rate_limit_without_retry_after_backs_off_by_attempt(
    fake: FakeGitHub, client: Client, sleeps: list[float]
) -> None:
    world(fake)
    body = '{"message": "You have exceeded a secondary rate limit. Please wait a few minutes."}'
    fake.faults.append(Fault(403, {}, body, times=2))
    client.execute(META, VARS)
    assert sleeps == [60.0, 120.0]


def test_a_rate_limit_that_never_ends_is_a_rate_limited_error_after_the_last_attempt(
    fake: FakeGitHub, sleeps: list[float]
) -> None:
    world(fake)
    fake.faults.append(Fault(429, {"Retry-After": "1"}, "{}", times=99))
    c = Client(fake.token, fake.url, sleep=sleeps.append, max_attempts=3)
    with pytest.raises(RateLimitedError):
        c.execute(META, VARS)
    assert len(sleeps) == 2


def test_a_reset_further_away_than_we_will_wait_is_not_waited_for(fake: FakeGitHub, sleeps: list[float]) -> None:
    world(fake)
    fake.faults.append(Fault(403, {"Retry-After": "3600"}, "{}", times=1))
    c = Client(fake.token, fake.url, sleep=sleeps.append, max_wait=120)
    with pytest.raises(RateLimitedError):
        c.execute(META, VARS)
    assert sleeps == []


def test_a_plain_403_is_a_refusal_not_a_rate_limit(fake: FakeGitHub, client: Client, sleeps: list[float]) -> None:
    fake.faults.append(Fault(403, {}, '{"message": "Resource not accessible by integration"}', times=1))
    with pytest.raises(AuthError, match="Projects"):
        client.execute(META, VARS)
    assert sleeps == [] and fake.requests == ["ProjectMetaOrg"]


def test_a_502_is_retried_with_backoff_and_then_succeeds(fake: FakeGitHub, client: Client, sleeps: list[float]) -> None:
    world(fake)
    fake.faults.append(Fault(502, {}, "bad gateway", times=2))
    client.execute(META, VARS)
    assert sleeps == [2.0, 4.0]


def test_a_503_that_never_clears_is_an_api_error(fake: FakeGitHub, sleeps: list[float]) -> None:
    fake.faults.append(Fault(503, {}, "", times=99))
    c = Client(fake.token, fake.url, sleep=sleeps.append, max_attempts=3)
    with pytest.raises(ApiError, match="503"):
        c.execute(META, VARS)


def test_an_unreachable_server_is_an_api_error_without_a_traceback(sleeps: list[float]) -> None:
    c = Client("t", "http://127.0.0.1:9/graphql", sleep=sleeps.append, max_attempts=2)
    with pytest.raises(ApiError, match="could not reach GitHub"):
        c.execute(META, VARS)


def test_missing_scopes_say_how_to_get_them(fake: FakeGitHub, client: Client) -> None:
    def needs_scope(f: FakeGitHub, v: dict[str, object]) -> dict[str, object]:
        raise GqlError("INSUFFICIENT_SCOPES", "Your token has not been granted the required scopes: ['read:project']")

    fake.handlers["NeedsScope"] = needs_scope
    with pytest.raises(AuthError, match="gh auth refresh -s project"):
        client.execute("query NeedsScope { viewer { login } }")


def test_pagination_follows_end_cursor_across_three_pages(fake: FakeGitHub, client: Client) -> None:
    fake.page_size = 2
    world(fake, extra_fields=2)  # Title, Assignees, Labels + 2 = 5 fields: pages of 2, 2, 1
    names = [n["name"] for n in client.nodes(FIELDS, VARS, ("organization", "projectV2", "fields"))]
    assert names == ["Title", "Assignees", "Labels", "Extra 0", "Extra 1"]
    assert fake.requests == ["ProjectFieldsOrg"] * 3


def test_pagination_through_a_missing_path_is_not_found(fake: FakeGitHub, client: Client) -> None:
    fake.add_owner("organization", "acme")
    with pytest.raises(ApiError, match="nothing at"):
        list(client.nodes(FIELDS, VARS, ("organization", "projectV2", "fields")))


def test_a_dry_run_sends_no_mutation_and_says_what_it_would_have_sent(fake: FakeGitHub) -> None:
    world(fake)
    out = io.StringIO()
    c = Client(fake.token, fake.url, dry_run=True, out=out)
    result = c.execute("mutation AddItem($p: ID!) { x }", {"p": "PVT_1"}, dry_result={"ok": True})
    assert result == {"ok": True}
    assert c.skipped == 1 and fake.requests == []
    assert 'dry run: would AddItem {"p": "PVT_1"}' in out.getvalue()
    c.execute(META, VARS)  # a query still goes out
    assert fake.requests == ["ProjectMetaOrg"]


def test_update_project_v2_field_is_never_sent(fake: FakeGitHub, client: Client) -> None:
    doc = (
        "mutation UpdateField($input: UpdateProjectV2FieldInput!) "
        "{ updateProjectV2Field(input: $input) { clientMutationId } }"
    )
    with pytest.raises(SafoError, match="updateProjectV2Field is never sent"):
        client.execute(doc, {"input": {"fieldId": "F", "singleSelectOptions": []}})
    assert fake.requests == []


def test_plain_http_is_refused_except_for_loopback() -> None:
    with pytest.raises(ConfigError, match="https"):
        Client("t", "http://api.example.org/graphql")
    Client("t", "http://127.0.0.1:1/graphql")
    Client("t", "https://api.github.com/graphql")
