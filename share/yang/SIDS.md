# Arcana's SIDs

YANG Schema Item iDentifiers (SIDs, RFC 9595) key every node, rpc,
notification, identity and structure on cblink's wire version 2
(PLAN-SDN-YANG, "cblink 2: the protocol"). This file records the numbers
Arcana uses and where they come from (step 0.5.1).

## Rules

- A SID is never reused or removed. An item that goes is marked
  obsolete in its `.sid` file; a module revision adds items at the end
  of its range.
- Modules with IETF ranges use them: `ietf-coreconf` 1000, `ietf-yang-types`
  1100, `ietf-inet-types` 1150, `iana-crypt-hash` 1200,
  `ietf-netconf-acm` 1250, `ietf-sid-file` 1300, `ietf-interfaces` 1500,
  `ietf-ip` 1600, `ietf-system` 1700, `iana-if-type` 1800 (IANA's "IETF
  YANG-SID Ranges", 2026-10-13).
- Every other module Arcana speaks, its own and the IETF modules that
  have no IETF range yet, takes SIDs from Arcana's block. No
  interoperation with another SID-keyed protocol is claimed for those
  until they have numbers of their own.

## The block

**Provisional: from 2^40 (1 099 511 627 776)**, a block Arcana chose
itself, as the plan says, until it holds one by registration.

| Range | Size | Module | `.sid` file |
|---|---:|---|---|
| 2^40 + 0 | 100 | `cblink` | `cblink/share/yang/cblink@2026-10-13.sid` (48 used) |

## To decide: a registered block

The plan's step 0.5.1 asks IANA for a SID mega-range (RFC 9595 §7,
Expert Review). Two things learnt since:

- **RFC 9997** (July 2026) gives every holder of an IANA Private
  Enterprise Number (PEN) SID ranges with no request: SIDs 3pp ppp
  p00 000 to 3pp ppp p99 999 (100 000, 64-bit) for PEN ppp ppp, and,
  for a PEN below 100 000, SIDs 3 ppp pp0 000 to 3 ppp pp9 999
  (10 000, 32-bit). A PEN is free and quick to register, and new ones
  are numbered around 66 000, so Arcana would get both. A mega-range
  request, by contrast, commits the requester to managing it for ten
  years (RFC 9595 §6.3.2).
- **The width matters on the wire.** A top-level key, or a delta into
  another block, is 9 bytes above 2^32 and 5 bytes below
  (`docs/notes/cblink-v2-frame-sizes.md`: Arcana's augment keyed from
  2^40 costs 7 bytes an entry over a near key). The 32-bit range of a
  PEN below 100 000 puts the `cblink` structures, at the top of every
  error, credit and close frame, at 5 bytes.

A PEN gives 10 000 32-bit SIDs: enough for `cblink` and Arcana's own
modules; the IETF modules without IETF ranges (some 5 000 data nodes in
`share/yang` alone, `ietf-l3vpn-ntw` the largest) would go in the
100 000 64-bit range, as deltas mostly, where their width counts little.
