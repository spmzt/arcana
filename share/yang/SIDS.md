# Arcana's SIDs

YANG Schema Item iDentifiers (SIDs, RFC 9595) key every node, rpc,
notification, identity and structure on cblink's wire. This file
records the numbers Arcana uses and where they come from.

## Rules

- A SID is never reused or removed. An item that goes is marked
  obsolete in its `.sid` file; a module revision adds items at the end
  of its range.
- Modules with IETF ranges use them: `ietf-coreconf` 1000, `ietf-yang-types`
  1100, `ietf-inet-types` 1150, `iana-crypt-hash` 1200,
  `ietf-netconf-acm` 1250, `ietf-sid-file` 1300, `ietf-interfaces` 1500,
  `ietf-ip` 1600, `ietf-system` 1700, `iana-if-type` 1800 (IANA's "IETF
  YANG-SID Ranges").
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
| `ietf-netconf-acm@2018-02-14` | 1250 | 50 | `ietf-netconf-acm@2018-02-14.sid` (26 used) |
| `ietf-interfaces@2018-02-20` | 1500 | 100 | `ietf-interfaces@2018-02-20.sid` (62 used) |
| `ietf-ip@2018-02-22` | 1600 | 100 | `ietf-ip@2018-02-22.sid` (63 used) |
| `iana-if-type@2026-03-17` | 1800 | 400 | `iana-if-type@2026-03-17.sid` (306 used) |

The CORECONF draft's examples number
`/ietf-interfaces:interfaces/interface` 1533, as here, but its
children otherwise (`description` 1534, `name` 1537, `type` 1538) and
`ethernetCsmacd` 1880, where these files have 1535, 1542, 1561 and
1893: the draft's are those of files made for the modules' 2014
revisions, which are not published where they can be fetched.
Interoperating with a CORECONF peer would need those files; Arcana
claims no such interoperation.

## The block

**RFC 9595's range for experimental use, 60 000 to 99 999** (section
6.4.2, IANA policy "Experimental Use"): free, needing no request. Its
SIDs are not globally unique, so RFC 9595 says they are for no
operational deployment: a peer that speaks another module numbered in
the same range would read our items as its own. Arcana claims no such
interoperation; a registered block replaces this one before it does
(below). Below 65 536, a top-level key or an identity's SID is 3 bytes
on the wire.

| Range | Size | Module | `.sid` file |
|---|---:|---|---|
| 60 000 | 100 | `cblink`, the framework's structures | `cblink/share/yang/cblink@2026-10-13.sid` (53 used) |
| 60 100 | 100 | `kv`, cblink's example | `cblink/examples/kv/kv@2026-10-13.sid` (22 used) |
| 60 200 | 100 | `cblink-ctrl`, the control family | `cblink/share/yang/cblink-ctrl@2026-10-13.sid` (47 used) |
| 60 300 | 100 | `echo`, cblink's example | `cblink/examples/echo/echo@2026-10-13.sid` (7 used) |
| 60 400 | 100 | `stream`, cblink's example | `cblink/examples/stream/stream@2026-10-13.sid` (5 used) |
| 60 500 | 100 | `notify`, cblink's example | `cblink/examples/notify/notify@2026-10-13.sid` (4 used) |
| 61 000 | 200 | `arcana-interfaces` | `share/yang/arcana-interfaces@2026-10-14.sid` (58 used, 29 obsolete: mtu, ether, hw-address, fib, epair and its two, vlan and its four, media's type, lagg and its six, bridge and its eight, which the standard models carry) |
| 61 200 | 100 | `arcana-ip-deviations` | `share/yang/arcana-ip-deviations@2026-10-14.sid` (1 used) |
| 61 300 | 200 | `ietf-routing@2018-03-13` (no IETF range) | `share/yang/ietf-routing@2018-03-13.sid` (89 used) |
| 61 500 | 100 | `ietf-ipv4-unicast-routing@2018-03-13` (no IETF range) | `share/yang/ietf-ipv4-unicast-routing@2018-03-13.sid` (29 used) |
| 61 600 | 100 | `ietf-ipv6-unicast-routing@2018-03-13` (no IETF range) | `share/yang/ietf-ipv6-unicast-routing@2018-03-13.sid` (66 used) |
| 61 700 | 100 | `arcana-routing` | `share/yang/arcana-routing@2026-10-14.sid` (14 used, 5 obsolete: its bgp, ospf, isis, rip and babel, which their own modules carry) |
| 61 800 | 100 | `ietf-network-instance@2019-01-21` (no IETF range) | `share/yang/ietf-network-instance@2019-01-21.sid` (21 used) |
| 61 900 | 100 | `arcana-network-instance` | `share/yang/arcana-network-instance@2026-10-14.sid` (2 used) |
| 62 000 | 100 | `ietf-logical-network-element@2019-01-25` (no IETF range) | `share/yang/ietf-logical-network-element@2019-01-25.sid` (12 used) |
| 62 100 | 100 | `arcana-jails` | `share/yang/arcana-jails@2026-10-14.sid` (53 used) |
| 62 200 | 100 | `arcana-services` | `share/yang/arcana-services@2026-10-14.sid` (79 used) |
| 62 300 | 100 | `arcana-packages` | `share/yang/arcana-packages@2026-10-14.sid` (100 used; its rest at 79 500) |
| 62 400 | 1 000 | `arcana-jobs`, its submodule `arcana-jobs-kinds` | `share/yang/arcana-jobs@2026-10-14.sid` (702 used, 34 obsolete: a job's steps in the state, now its read action's, and each kind's safe, now the change's; the dry-run rpc, its changes submit's again; room for the kinds to come; its rest at 83 200) |
| 63 400 | 200 | `arcana-storage` | `share/yang/arcana-storage@2026-10-14.sid` (200 used, 9 obsolete: a snapshot's send action and the receive rpc, arcana-stream's now; its rest at 79 600) |
| 63 600 | 100 | `arcana-sysctl` | `share/yang/arcana-sysctl@2026-10-14.sid` (12 used) |
| 63 700 | 100 | `arcana-kernel` | `share/yang/arcana-kernel@2026-10-14.sid` (37 used) |
| 63 800 | 100 | `arcana-processes`, `openconfig-procmon`'s grouping used in it | `share/yang/arcana-processes@2026-10-14.sid` (90 used) |
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
| 69 900 | 100 | `arcana-log` | `share/yang/arcana-log@2026-10-14.sid` (35 used) |
| 70 000 | 200 | `ietf-syslog@2025-04-30`, RFC 9742 (no IETF range) | `share/yang/ietf-syslog@2025-04-30.sid` (109 used) |
| 70 200 | 300 | `arcana-firewall` | `share/yang/arcana-firewall@2026-10-15.sid` (223 used; its rest at 84 700) |
| 70 500 | 200 | `arcana-troubleshoot` | `share/yang/arcana-troubleshoot@2026-10-15.sid` (157 used) |
| 70 700 | 100 | `arcana-history` | `share/yang/arcana-history@2026-10-15.sid` (100 used; its rest at 80 000) |
| 70 800 | 400 | `arcana-events` | `share/yang/arcana-events@2026-10-15.sid` (400 used; its rest at 80 100) |
| 71 200 | 200 | `arcana-bird` | `share/yang/arcana-bird@2026-10-15.sid` (200 used, 170 obsolete with the second range's: the jail augment, the actions' jail input and arcana-bird's jail in its place; its rest at 80 400) |
| 71 400 | 100 | `arcana-wireguard` | `share/yang/arcana-wireguard@2026-10-15.sid` (70 used, 34 obsolete: the jail augment, the read action's jail input in its place) |
| 71 500 | 100 | `arcana-netgraph` | `share/yang/arcana-netgraph@2026-10-15.sid` (50 used, 24 obsolete: the jail augment, the read action's jail input in its place) |
| 71 600 | 100 | `arcana-host` | `share/yang/arcana-host@2026-10-15.sid` (100 used, 34 obsolete: the host's certificates, a read-certificates action's output now; its rest at 82 000 and 83 000) |
| 71 700 | 200 | `arcana-agent` | `share/yang/arcana-agent@2026-10-15.sid` (200 used, 1 obsolete: the certificate's chain as subjects, its intermediate certificates now; its rest at 82 100 and 83 100) |
| 71 900 | 100 | `arcana-jail-files` | `share/yang/arcana-jail-files@2026-10-15.sid` (25 used, 11 obsolete: the jails' files as state, the read-files action's output now) |
| 72 000 | 100 | `arcana-probe` | `share/yang/arcana-probe@2026-10-15.sid` (100 used, 1 obsolete: a target's jail, the jail list's now; its rest at 80 300) |
| 72 100 | 200 | `arcana-sdwan` | `share/yang/arcana-sdwan@2026-10-15.sid` (200 used, 3 obsolete: the rules' and the steer's jail, the jail list's now, and a proxy's deny, which its form says; its rest at 81 000) |
| 72 300 | 100 | `arcana-sshd` | `share/yang/arcana-sshd@2026-10-15.sid` (69 used, 35 obsolete: the jail augment, the read action's jail input in its place, and user-ca, the user-ca-key list now; its rest at 85 000) |
| 72 400 | 200 | `arcana-builder` | `share/yang/arcana-builder@2026-10-17.sid` (98 used) |
| 72 600 | 100 | `arcana-notify` | `share/yang/arcana-notify@2026-10-17.sid` (7 used) |
| 73 000 | 4 000 | `arcana`, once the wire of the interim family, now the structures the programs keep (`share/arcana/arcana.yaml`, written by `share/arcana/wire.awk`: a jail, a service, a job and its change) | `share/yang/arcana@2026-10-22.sid` (1 838 used, 1 724 obsolete: every rpc, notification and stream payload of the family, retired with it (0.238.0/0.336.0), and the sets nothing keeps; `make regen-wire` numbers a new item, `make check-wire` holds the rest) |
| 77 000 | 200 | `arcana-cluster`, the consoles' own family (`share/arcana/cluster.yaml`) | `share/yang/arcana-cluster@2026-10-22.sid` (84 used) |
| 77 200 | 100 | `ietf-yang-library@2019-01-04`, RFC 8525 (no IETF range) | `share/yang/ietf-yang-library@2019-01-04.sid` (51 used) |
| 77 300 | 100 | `ietf-datastores@2018-02-14`, RFC 8342 (no IETF range; its identities used) | `share/yang/ietf-datastores@2018-02-14.sid` (9 used) |
| 77 400 | 200 | `ietf-alarms@2019-09-11`, RFC 8632 (no IETF range) | `share/yang/ietf-alarms@2019-09-11.sid` (183 used) |
| 77 600 | 100 | `arcana-alarms` | `share/yang/arcana-alarms@2026-10-27.sid` (17 used) |
| 77 700 | 200 | `ietf-hardware@2018-03-13`, RFC 8348 (no IETF range) | `share/yang/ietf-hardware@2018-03-13.sid` (51 used) |
| 77 900 | 100 | `iana-hardware@2018-03-13`, RFC 8348's classes (no IETF range) | `share/yang/iana-hardware@2018-03-13.sid` (16 used) |
| 78 000 | 200 | `ietf-subscribed-notifications@2019-09-09`, RFC 8639 (no IETF range) | `share/yang/ietf-subscribed-notifications@2019-09-09.sid` (156 used) |
| 78 200 | 200 | `ietf-yang-push@2019-09-09`, RFC 8641 (no IETF range) | `share/yang/ietf-yang-push@2019-09-09.sid` (118 used) |
| 78 400 | 100 | `arcana-fleet`, the console's RESTCONF fleet mount | `share/yang/arcana-fleet@2026-10-27.sid` (5 used) |
| 78 500 | 200 | `ietf-netconf@2011-06-01`, RFC 6241: commit, cancel-commit, discard-changes (no IETF range) | `share/yang/ietf-netconf@2011-06-01.sid` (107 used) |
| 78 700 | 100 | `ietf-origin@2018-02-14`, RFC 8342: the `origin` annotation and its identities, for a GET's with-origin (no IETF range) | `share/yang/ietf-origin@2018-02-14.sid` (9 used) |
| 78 800 | 100 | `ietf-defaults@2024-04-03`, draft-ietf-netconf-default-attribute: RFC 6243's `default` annotation, for report-all-tagged (no IETF range) | `share/yang/ietf-defaults@2024-04-03.sid` (2 used) |
| 78 900 | 100 | `ietf-yang-schema-mount@2019-01-14`, RFC 8528: `schema-mounts`, the mount points served (no IETF range) | `share/yang/ietf-yang-schema-mount@2019-01-14.sid` (12 used) |
| 79 000 | 100 | `ietf-subscribed-notif-receivers@2026-06-30`, draft-ietf-netconf-https-notif: the receiver instances a configured subscription's receivers name (no IETF range) | `share/yang/ietf-subscribed-notif-receivers@2026-06-30.sid` (5 used) |
| 79 100 | 100 | `ietf-https-notif-transport@2026-06-30`, draft-ietf-netconf-https-notif: the https-receiver, its endpoints (no IETF range) | `share/yang/ietf-https-notif-transport@2026-06-30.sid` (19 used) |
| 79 200 | 100 | `ietf-http-client@2024-08-15`, draft-ietf-netconf-http-client-server: imported alone, its groupings the endpoints' (no IETF range) | `share/yang/ietf-http-client@2024-08-15.sid` (6 used) |
| 79 300 | 100 | `arcana-notif`, the https-receiver's bearer token | `share/yang/arcana-notif@2026-10-28.sid` (2 used) |
| 79 400 | 100 | `arcana-ra`, rtadvd.conf(5) beyond RFC 8349 and rtadvctl(8) show | `share/yang/arcana-ra@2026-10-28.sid` (61 used) |
| 79 500 | 100 | `arcana-packages`, its second range: the read action, pkgbase, the refresh action's update, ignore-osversion and output, every-jail | `share/yang/arcana-packages@2026-10-14.sid` (17 used) |
| 79 600 | 200 | `arcana-storage`, its second range: the read action's output, create-encrypted | `share/yang/arcana-storage@2026-10-14.sid` (76 used) |
| 80 000 | 100 | `arcana-history`, its second range: the read action's settings and totals | `share/yang/arcana-history@2026-10-15.sid` (3 used) |
| 80 100 | 100 | `arcana-events`, its second range: a route's nexthop and paths, a neighbour's family, a tunnel's jail, undo-failed's data, the read's kept | `share/yang/arcana-events@2026-10-15.sid` (22 used) |
| 80 300 | 100 | `arcana-probe`, its second range: the links, the monitors, the jails' edges, the read action's whole targets | `share/yang/arcana-probe@2026-10-15.sid` (64 used) |
| 80 400 | 300 | `arcana-bird`, its second range: the read, ospf and check actions, a protocol's detail, the jails' configuration | `share/yang/arcana-bird@2026-10-15.sid` (153 used) |
| 81 000 | 200 | `arcana-sdwan`, its second range: the forms (spec, host), the jails' edges, the breakout's routes, a rule's place, the IDS' and the proxies' settings, the apply action, the state's routes, bfd, ClamAV and the IDS' build, host, ruleset, statistics and captures | `share/yang/arcana-sdwan@2026-10-15.sid` (122 used) |
| 82 000 | 100 | `arcana-host`, its second range: the read-certificates action, the plugins poudriere, smtpd and speederv2 | `share/yang/arcana-host@2026-10-15.sid` (17 used) |
| 82 100 | 100 | `arcana-agent`, its second range: the transport's time, the TLS chain's certificates | `share/yang/arcana-agent@2026-10-15.sid` (7 used) |
| 83 000 | 100 | `arcana-host`, its third range: the agent's features and safe-wait, what hello said | `share/yang/arcana-host@2026-10-15.sid` (2 used) |
| 83 100 | 100 | `arcana-agent`, its third range: update's program-size, build's compress and program-size, a fetch's refusal, console-update's commit | `share/yang/arcana-agent@2026-10-15.sid` (8 used) |
| 83 200 | 100 | `arcana-jobs`, its second range: the steps notification, a request's trace told to its peer as it runs | `share/yang/arcana-jobs@2026-10-14.sid` (13 used) |
| 84 000 | 700 | `arcana-network`: the network tables' read actions (routes, nexthops, nexthop groups, connections, sockets, interfaces, bridges, geneve, neighbours, multicast, kept routes, IPsec, a jail's firewall, the route lookup), the network-part structure, a jail's address action | `share/yang/arcana-network@2026-10-29.sid` (639 used) |
| 84 700 | 100 | `arcana-firewall`, its second range (listed first in its file, so that new items go there): a kept rule's norm, the pipes' lines, the vnet jails' kept rules, the check and from-rc actions, the state's tunables, modules and a table's set | `share/yang/arcana-firewall@2026-10-15.sid` (60 used) |
| 85 000 | 100 | `arcana-sshd`, its second range: the read action, the user CAs' keys and text, sshd_config's path, a certificate's serial | `share/yang/arcana-sshd@2026-10-15.sid` (54 used) |
| 85 100 | 100 | `arcana-probe`, its third range: the read action's monitors | `share/yang/arcana-probe@2026-10-15.sid` (1 used) |
| 85 200 | 100 | `arcana-crashes` | `share/yang/arcana-crashes@2026-10-29.sid` (22 used) |
| 85 300 | 100 | `arcana-system` | `share/yang/arcana-system@2026-10-29.sid` (58 used) |
| 85 400 | 100 | `arcana-netstore` | `share/yang/arcana-netstore@2026-10-29.sid` (48 used) |
| 85 500 | 200 | `arcana-suricata` | `share/yang/arcana-suricata@2026-10-29.sid` (132 used) |
| 85 700 | 100 | `arcana-smtpd` | `share/yang/arcana-smtpd@2026-10-29.sid` (68 used) |
| 85 800 | 160 | `arcana-speeder` | `share/yang/arcana-speeder@2026-10-29.sid` (156 used) |
| 85 960 | 40 | `arcana-stream`, the structures of Arcana's own stream family | `share/yang/arcana-stream@2026-10-29.sid` (9 used) |

cblink's modules take 60 000 to 60 999; Arcana's own follow from
61 000. cblink's own test modules (`shapes` from 2^40 + 100 000,
`rules` from 2^40 + 200 000, the annotation examples at
draft-ietf-core-yang-metadata's 61 600 to 61 631) number themselves for
its tests and are never on a wire.

## A registered block

What replaces the experimental range once Arcana interoperates with
another SID-keyed peer: an IANA SID mega-range (RFC 9595 §7, Expert
Review), or the ranges of a Private Enterprise Number.

- **RFC 9997** gives every holder of an IANA Private Enterprise Number
  (PEN) SID ranges with no request: SIDs 3pp ppp p00 000 to 3pp ppp
  p99 999 (100 000, 64-bit) for PEN ppp ppp, and, for a PEN below
  100 000, SIDs 3 ppp pp0 000 to 3 ppp pp9 999 (10 000, 32-bit). A PEN
  is free and quick to register, and new ones are numbered around
  66 000, so Arcana would get both. A mega-range request, by contrast,
  commits the requester to managing it for ten years (RFC 9595
  §6.3.2).
- **The width matters on the wire.** A top-level key, or a delta into
  another block, is 9 bytes above 2^32 and 5 bytes below. The 32-bit
  range of a PEN below 100 000 puts the `cblink` structures, at the top
  of every error, credit and close frame, at 5 bytes.

A PEN gives 10 000 32-bit SIDs: enough for `cblink` and Arcana's own
modules; the IETF modules without IETF ranges (some 5 000 data nodes in
`share/yang` alone, `ietf-l3vpn-ntw` the largest) would go in the
100 000 64-bit range, as deltas mostly, where their width counts little.
