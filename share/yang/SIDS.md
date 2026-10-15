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
  have no IETF range yet, takes SIDs from Arcana's block, below. No
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

**For now: RFC 9595's range for experimental use, 60 000 to 99 999**
(section 6.4.2, IANA policy "Experimental Use"), the user's decision of
2026-10-14: free, needing no request. Its SIDs are not globally unique,
so RFC 9595 says they are for no operational deployment: a peer that
speaks another module numbered in the same range would read our items
as its own. Arcana claims no such interoperation; a registered block
replaces this one before it does (below). The modules kept their places
in the provisional block Arcana chose first, from 2^40: 2^40 + X became
60 000 + X. Below 65 536, a top-level key or an identity's SID is 3
bytes on the wire, where it was 9.

| Range | Size | Module | `.sid` file |
|---|---:|---|---|
| 60 000 | 100 | `cblink`, the framework's structures | `cblink/share/yang/cblink@2026-10-13.sid` (50 used) |
| 60 100 | 100 | `kv`, cblink's example | `cblink/examples/kv/kv@2026-10-13.sid` (22 used) |
| 60 200 | 100 | `cblink-ctrl`, the control family | `cblink/share/yang/cblink-ctrl@2026-10-13.sid` (47 used) |
| 60 300 | 100 | `echo`, cblink's example | `cblink/examples/echo/echo@2026-10-13.sid` (7 used) |
| 60 400 | 100 | `stream`, cblink's example | `cblink/examples/stream/stream@2026-10-13.sid` (5 used) |
| 60 500 | 100 | `notify`, cblink's example | `cblink/examples/notify/notify@2026-10-13.sid` (4 used) |
| 61 000 | 200 | `arcana-interfaces` | `share/yang/arcana-interfaces@2026-10-14.sid` (53 used, 29 obsolete: mtu, ether, hw-address, fib, epair and its two, vlan and its four, media's type, lagg and its six, bridge and its eight, now the standard models') |
| 61 200 | 100 | `arcana-ip-deviations` | `share/yang/arcana-ip-deviations@2026-10-14.sid` (1 used) |
| 61 300 | 200 | `ietf-routing@2018-03-13` (no IETF range) | `share/yang/ietf-routing@2018-03-13.sid` (89 used) |
| 61 500 | 100 | `ietf-ipv4-unicast-routing@2018-03-13` (no IETF range) | `share/yang/ietf-ipv4-unicast-routing@2018-03-13.sid` (29 used) |
| 61 600 | 100 | `ietf-ipv6-unicast-routing@2018-03-13` (no IETF range) | `share/yang/ietf-ipv6-unicast-routing@2018-03-13.sid` (66 used) |
| 61 700 | 100 | `arcana-routing` | `share/yang/arcana-routing@2026-10-14.sid` (14 used, 5 obsolete: its bgp, ospf, isis, rip and babel, now their modules') |
| 61 800 | 100 | `ietf-network-instance@2019-01-21` (no IETF range) | `share/yang/ietf-network-instance@2019-01-21.sid` (21 used) |
| 61 900 | 100 | `arcana-network-instance` | `share/yang/arcana-network-instance@2026-10-14.sid` (2 used) |
| 62 000 | 100 | `ietf-logical-network-element@2019-01-25` (no IETF range) | `share/yang/ietf-logical-network-element@2019-01-25.sid` (12 used) |
| 62 100 | 100 | `arcana-jails` | `share/yang/arcana-jails@2026-10-14.sid` (51 used) |
| 62 200 | 100 | `arcana-services` | `share/yang/arcana-services@2026-10-14.sid` (39 used) |
| 62 300 | 100 | `arcana-packages` | `share/yang/arcana-packages@2026-10-14.sid` (59 used) |
| 62 400 | 1 000 | `arcana-jobs`, its submodule `arcana-jobs-kinds` | `share/yang/arcana-jobs@2026-10-14.sid` (273 used; room for the kinds to come) |
| 63 400 | 200 | `arcana-storage` | `share/yang/arcana-storage@2026-10-14.sid` (144 used) |
| 63 600 | 100 | `arcana-sysctl` | `share/yang/arcana-sysctl@2026-10-14.sid` (12 used) |
| 63 700 | 100 | `arcana-kernel` | `share/yang/arcana-kernel@2026-10-14.sid` (37 used) |
| 63 800 | 100 | `arcana-processes`, `openconfig-procmon`'s grouping used in it | `share/yang/arcana-processes@2026-10-14.sid` (66 used) |
| 63 900 | 1 900 | `ietf-ospf@2022-10-19` (no IETF range; its identities used) | `share/yang/ietf-ospf@2022-10-19.sid` (1 725 used) |
| 65 800 | 200 | `ietf-rip@2020-02-20` (no IETF range; its identities used) | `share/yang/ietf-rip@2020-02-20.sid` (158 used) |
| 66 000 | 1 000 | `ietf-isis@2022-10-19` (no IETF range; its identities used) | `share/yang/ietf-isis@2022-10-19.sid` (821 used) |
| 67 000 | 200 | `ietf-babel@2024-10-10` (no IETF range; its identities used) | `share/yang/ietf-babel@2024-10-10.sid` (103 used) |
| 67 200 | 1 000 | `ietf-bgp@2026-08-14`, draft-ietf-idr-bgp-model (its identities used) | `share/yang/ietf-bgp@2026-08-14.sid` (830 used) |
| 68 200 | 100 | `ietf-bfd-types@2022-09-22` (no IETF range; bfdv1 is a routing protocol) | `share/yang/ietf-bfd-types@2022-09-22.sid` (15 used) |
| 68 300 | 100 | `ietf-if-extensions@2025-08-07`, draft-ietf-netmod-intf-ext-yang | `share/yang/ietf-if-extensions@2025-08-07.sid` (36 used) |
| 68 400 | 100 | `ietf-if-ethernet-like@2026-06-19`, draft-ietf-netmod-intf-ext-yang | `share/yang/ietf-if-ethernet-like@2026-06-19.sid` (26 used) |
| 68 500 | 100 | `ietf-if-vlan-encapsulation@2026-07-06`, draft-ietf-netmod-sub-intf-vlan-model | `share/yang/ietf-if-vlan-encapsulation@2026-07-06.sid` (8 used) |
| 68 600 | 100 | `ieee802-dot1q-types@2023-10-26`, IEEE 802.1Q (no SIDs of IEEE's; its identities used) | `share/yang/ieee802-dot1q-types@2023-10-26.sid` (11 used) |
| 68 700 | 100 | `ieee802-ethernet-interface@2025-09-10`, IEEE 802.3 | `share/yang/ieee802-ethernet-interface@2025-09-10.sid` (63 used) |
| 68 800 | 300 | `ieee802-ethernet-phy-type@2025-09-10`, IEEE 802.3 (its PHY and PMD identities used) | `share/yang/ieee802-ethernet-phy-type@2025-09-10.sid` (253 used) |
| 69 100 | 100 | `ieee802-dot1ax-linkagg@2025-09-30`, IEEE 802.1AX | `share/yang/ieee802-dot1ax-linkagg@2025-09-30.sid` (85 used) |
| 69 200 | 100 | `ieee802-dot1ax-types@2025-09-30`, IEEE 802.1AX (its identities used) | `share/yang/ieee802-dot1ax-types@2025-09-30.sid` (26 used) |
| 69 300 | 100 | `arcana-ieee802-deviations` | `share/yang/arcana-ieee802-deviations@2026-10-14.sid` (1 used) |
| 69 400 | 300 | `ieee802-dot1q-bridge@2023-10-26`, IEEE 802.1Q | `share/yang/ieee802-dot1q-bridge@2023-10-26.sid` (262 used) |
| 69 700 | 100 | `ieee802-dot1q-rstp@2025-02-04`, IEEE 802.1Q (groupings only) | `share/yang/ieee802-dot1q-rstp@2025-02-04.sid` (1 used) |
| 69 800 | 100 | `ieee802-dot1q-rstp-bridge@2025-02-04`, IEEE 802.1Q | `share/yang/ieee802-dot1q-rstp-bridge@2025-02-04.sid` (58 used) |
| 69 900 | 100 | `arcana-log` | `share/yang/arcana-log@2026-10-14.sid` (30 used) |
| 70 000 | 200 | `ietf-syslog@2025-04-30`, RFC 9742 (no IETF range) | `share/yang/ietf-syslog@2025-04-30.sid` (109 used) |
| 70 200 | 300 | `arcana-firewall` | `share/yang/arcana-firewall@2026-10-15.sid` (223 used) |
| 70 500 | 200 | `arcana-troubleshoot` | `share/yang/arcana-troubleshoot@2026-10-15.sid` (148 used) |
| 70 700 | 100 | `arcana-history` | `share/yang/arcana-history@2026-10-15.sid` (71 used) |
| 70 800 | 400 | `arcana-events` | `share/yang/arcana-events@2026-10-15.sid` (275 used) |

cblink's modules take 60 000 to 60 999; Arcana's own follow from
61 000. cblink's own test modules (`shapes` from 2^40 + 100 000,
`rules` from 2^40 + 200 000, the annotation examples at
draft-ietf-core-yang-metadata's 61 600 to 61 631) number themselves for
its tests and are never on a wire.

## Later: a registered block

What replaces the experimental range once Arcana interoperates with
another SID-keyed peer. The plan's step 0.5.1 asks IANA for a SID
mega-range (RFC 9595 §7, Expert Review). Two things learnt since:

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
