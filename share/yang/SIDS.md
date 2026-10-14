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
- IANA publishes the ranges, not always the `.sid` files. For
  `ietf-sid-file` it has none, so cblink's
  `share/yang/ietf-sid-file@2024-07-31.sid` numbers it as RFC 9595
  Appendix B says (`cblink-gen -a`): 1300 the module, 1301 the
  `sid-file` structure, 1302 to 1317 its nodes in path order. GET-SID's
  YANG-CBOR is keyed by those; if IANA ever publishes other numbers,
  they replace these.
- Every other module Arcana speaks, its own and the IETF modules that
  have no IETF range yet, takes SIDs from Arcana's block. No
  interoperation with another SID-keyed protocol is claimed for those
  until they have numbers of their own.

## The IETF ranges, numbered here

IANA's registry gives ranges and publishes no `.sid` file for them
("IETF YANG-SID Modules: no registrations"), so Arcana numbers each
module in its range as RFC 9595 Appendix B says (`cblink-gen -a`), as
for `ietf-sid-file`:

| Module | Range | Size | `.sid` file |
|---|---:|---:|---|
| `ietf-yang-types@2025-12-22` | 1100 | 50 | `ietf-yang-types@2025-12-22.sid` (1 used) |
| `ietf-inet-types@2025-12-22` | 1150 | 50 | `ietf-inet-types@2025-12-22.sid` (1 used) |
| `ietf-interfaces@2018-02-20` | 1500 | 100 | `ietf-interfaces@2018-02-20.sid` (62 used) |
| `ietf-ip@2018-02-22` | 1600 | 100 | `ietf-ip@2018-02-22.sid` (63 used) |
| `iana-if-type@2026-03-17` | 1800 | 400 | `iana-if-type@2026-03-17.sid` (306 used) |

**To decide (the user's):** the CORECONF draft's examples number
`/ietf-interfaces:interfaces/interface` 1533, as here, but its
children otherwise (`description` 1534, `name` 1537, `type` 1538) and
`ethernetCsmacd` 1880, where these files have 1535, 1542, 1561 and
1893: the draft's are those of files made for the modules' 2014
revisions, extended since, which are not published where they can be
fetched. Interoperating with a CORECONF peer would need those files;
Arcana claims no such interoperation yet.

## The block

**Provisional: from 2^40 (1 099 511 627 776)**, a block Arcana chose
itself, as the plan says, until it holds one by registration.

| Range | Size | Module | `.sid` file |
|---|---:|---|---|
| 2^40 + 0 | 100 | `cblink`, the framework's structures | `cblink/share/yang/cblink@2026-10-13.sid` (50 used) |
| 2^40 + 100 | 100 | `kv`, cblink's example | `cblink/examples/kv/kv@2026-10-13.sid` (22 used) |
| 2^40 + 200 | 100 | `cblink-ctrl`, the control family | `cblink/share/yang/cblink-ctrl@2026-10-13.sid` (47 used) |
| 2^40 + 300 | 100 | `echo`, cblink's example | `cblink/examples/echo/echo@2026-10-13.sid` (7 used) |
| 2^40 + 400 | 100 | `stream`, cblink's example | `cblink/examples/stream/stream@2026-10-13.sid` (5 used) |
| 2^40 + 500 | 100 | `notify`, cblink's example | `cblink/examples/notify/notify@2026-10-13.sid` (4 used) |
| 2^40 + 1000 | 200 | `arcana-interfaces` | `share/yang/arcana-interfaces@2026-10-14.sid` (46 used) |
| 2^40 + 1200 | 100 | `arcana-ip-deviations` | `share/yang/arcana-ip-deviations@2026-10-14.sid` (1 used) |
| 2^40 + 1300 | 200 | `ietf-routing@2018-03-13` (no IETF range) | `share/yang/ietf-routing@2018-03-13.sid` (89 used) |
| 2^40 + 1500 | 100 | `ietf-ipv4-unicast-routing@2018-03-13` (no IETF range) | `share/yang/ietf-ipv4-unicast-routing@2018-03-13.sid` (29 used) |
| 2^40 + 1600 | 100 | `ietf-ipv6-unicast-routing@2018-03-13` (no IETF range) | `share/yang/ietf-ipv6-unicast-routing@2018-03-13.sid` (66 used) |
| 2^40 + 1700 | 100 | `arcana-routing` | `share/yang/arcana-routing@2026-10-14.sid` (14 used) |
| 2^40 + 1800 | 100 | `ietf-network-instance@2019-01-21` (no IETF range) | `share/yang/ietf-network-instance@2019-01-21.sid` (21 used) |
| 2^40 + 1900 | 100 | `arcana-network-instance` | `share/yang/arcana-network-instance@2026-10-14.sid` (2 used) |
| 2^40 + 2000 | 100 | `ietf-logical-network-element@2019-01-25` (no IETF range) | `share/yang/ietf-logical-network-element@2019-01-25.sid` (12 used) |

cblink's modules take 2^40 to 2^40 + 999; Arcana's own follow from
2^40 + 1000. cblink's own test modules (`shapes` from 2^40 + 100 000,
`rules` from 2^40 + 200 000) number themselves for its tests and are
never on a wire. cblink's paths are its branch v2, which arcana takes
at the switch.

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
