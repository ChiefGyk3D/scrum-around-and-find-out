# SPDX-License-Identifier: Apache-2.0
"""The paid-path broker core (#205, phase 1): pure, deterministic pieces with no socket, no service and no vendor call.

Design: docs/gemini-broker.md. This package holds integer micro-dollar arithmetic, the price table, the caps and the
model allow-list, the call state machine, the schema version 3 approval and ledger records, and the ledger that spends
before a call is sent. Nothing here reads a key, opens a network connection or starts a process.
"""
