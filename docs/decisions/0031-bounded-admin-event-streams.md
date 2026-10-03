# ADR 0031: Bound administrative event streams and revalidate grants

Status: Accepted
Date: 2026-10-03
Task: REVIEW-EVENT-01

## Context

Event history is bounded, but long-lived REST SSE and MCP listen handlers could
consume unbounded subscriptions. Authorization at stream opening also allowed a
revoked or expired credential to continue receiving bodies or notifications.
Concurrent event acceptance could reorder delivery and mutable event payloads
could alias retained history.

## Decision

Use a fixed process-wide limit of 128 live stream admissions on the shared event
ring. REST SSE and every MCP listen, including metadata-only listens, consume one
slot. Saturation fails closed with domain `unavailable` and HTTP 503 before SSE
headers or an MCP acknowledgment. Slow-consumer detachment does not release the
admission until the owning handler exits. Cancellation releases it exactly once.
The channel buffer is bounded by ring capacity. Future configurable admission
limits are deliberately deferred; this change adds no public configuration key.

Serialize nonblocking fanout with ID assignment. Store independent event argument
slices and timestamp pointers and return independent copies to every reader,
subscriber, and stdout consumer. Replay captures all matching retained entries in
one finite, ring-capacity-bounded window after subscribing, then resumes live
ordered delivery and skips duplicate IDs. An overwritten cursor sends reset.

Bind streams to the authenticated token incarnation. Recheck current token
existence, enablement, expiry, and grants before event sends and heartbeats. REST
also checks its UI session without updating session idle activity. Grant loss or
session invalidation terminates the stream; losing `events:sensitive` terminates
rather than mixing views. MCP checks all initially granted scopes, including
those relevant to resource and discovery notifications. No plaintext credential
is added to stream state.

## Alternatives

A configurable limit would expand the public schema before the lab needs that
complexity. Separate REST and MCP limits would let one adapter evade the shared
resource budget. Paging replay until the live ring stops growing could run
indefinitely; a finite captured window provides a deterministic handoff. Reusing
ordinary cookie authentication on heartbeats would incorrectly keep idle browser
sessions alive. Reauthenticating raw bearers would retain unnecessary secrets.

## Consequences and compatibility

The 129th concurrent stream is rejected until a slot is released. Slow subscribers
still receive the existing reset/complete behavior and must reconnect. Revoked,
expired, rotated, or narrowed credentials close existing streams by their next
send or heartbeat. Existing paged event queries, schemas, filters, and scope
names remain unchanged. Event copies add bounded allocation cost for events with
arguments or timestamp pointers; credential isolation takes precedence over
zero-copy fanout.

## Migration

No configuration migration is required. Clients should reconnect after closure
using valid credentials and REST Last-Event-ID, and back off after HTTP 503.
Background SSE traffic no longer extends UI session idle lifetime.

## Test and documentation impact

Ring regression tests cover actual concurrent ordering, independent ownership,
capacity rejection, cleanup, and closed-ring rejection. REST tests cover more
than 200 retained events with live handoff and revoked-stream termination. MCP
tests cover revoked notification streams and metadata-only capacity admission.
Auth tests cover token expiry, recreation, grant loss, session deletion, and idle
expiry without a heartbeat touch. Event fanout benchmarks record copy costs.
API_PARITY, MCP, architecture, tasks, and benchmark history describe the shared
contract; protocol conformance and public schemas do not change.
