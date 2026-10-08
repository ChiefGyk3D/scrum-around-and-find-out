# SPDX-License-Identifier: MIT
"""The writes: add an item, set a field by the item's node id, clear a field.

Fields are always set by the node id `addProjectV2ItemById` returned, never by looking the item up in a
listing: a fresh item can be missing from listings for a while. Every write must answer with the id of what
it wrote; an answer without it (or with another item's) is an UnknownOutcomeError, because the write may
have landed. Only a later read can say, and the caller re-reads; a mutation is never sent twice.
"""

from __future__ import annotations

from safo.errors import UnknownOutcomeError
from safo.graphql import Client
from safo.live import LiveBoard
from safo.mutation import mutate

M_ADD_ITEM = """mutation AddItem($projectId: ID!, $contentId: ID!) {
  addProjectV2ItemById(input: {projectId: $projectId, contentId: $contentId}) { item { id } }
}"""

M_SET_SELECT = """mutation SetSelect($projectId: ID!, $itemId: ID!, $fieldId: ID!, $optionId: String!) {
  updateProjectV2ItemFieldValue(
    input: {projectId: $projectId, itemId: $itemId, fieldId: $fieldId, value: {singleSelectOptionId: $optionId}}
  ) { projectV2Item { id } }
}"""

M_SET_DATE = """mutation SetDate($projectId: ID!, $itemId: ID!, $fieldId: ID!, $date: Date!) {
  updateProjectV2ItemFieldValue(
    input: {projectId: $projectId, itemId: $itemId, fieldId: $fieldId, value: {date: $date}}
  ) { projectV2Item { id } }
}"""

M_CLEAR_FIELD = """mutation ClearField($projectId: ID!, $itemId: ID!, $fieldId: ID!) {
  clearProjectV2ItemFieldValue(input: {projectId: $projectId, itemId: $itemId, fieldId: $fieldId}) {
    projectV2Item { id }
  }
}"""

DRY_ITEM = {"addProjectV2ItemById": {"item": {"id": "DRY_RUN"}}}


class Applier:
    def __init__(self, client: Client, live: LiveBoard) -> None:
        self._client = client
        self._live = live

    def add(self, content_id: str) -> str:
        """Add an issue or pull request; adding one that is already on the board returns its existing item."""
        data = mutate(
            self._client,
            M_ADD_ITEM,
            {"projectId": self._live.id, "contentId": content_id},
            dry_result=DRY_ITEM,
            returns=("addProjectV2ItemById", "item"),
        )
        return str(data["addProjectV2ItemById"]["item"]["id"])

    def set_select(self, item_id: str, field_name: str, option_name: str) -> None:
        variables = {
            "projectId": self._live.id,
            "itemId": item_id,
            "fieldId": self._live.field(field_name).id,
            "optionId": self._live.option_id(field_name, option_name),
        }
        self._write(M_SET_SELECT, variables, "updateProjectV2ItemFieldValue")

    def set_date(self, item_id: str, field_name: str, day: str) -> None:
        variables = {
            "projectId": self._live.id,
            "itemId": item_id,
            "fieldId": self._live.field(field_name).id,
            "date": day,
        }
        self._write(M_SET_DATE, variables, "updateProjectV2ItemFieldValue")

    def clear(self, item_id: str, field_name: str) -> None:
        variables = {"projectId": self._live.id, "itemId": item_id, "fieldId": self._live.field(field_name).id}
        self._write(M_CLEAR_FIELD, variables, "clearProjectV2ItemFieldValue")

    def _write(self, document: str, variables: dict[str, str], root: str) -> None:
        data = mutate(self._client, document, variables, dry_result={}, returns=(root, "projectV2Item"))
        if not self._client.dry_run and data[root]["projectV2Item"]["id"] != variables["itemId"]:
            raise UnknownOutcomeError(
                f"{root}: the reply names a different item than the one written, so it is not known "
                "what changed; re-read state before retrying, do not simply resend it",
                data=data,
                errors=[],
                status=200,
            )
