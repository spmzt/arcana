# Frame sizes: an interfaces read, wire version 1 against version 2

Step 0.1.4 of [../PLAN-SDN-YANG.md](../PLAN-SDN-YANG.md), measured
2026-10-13 on the lab VM (FreeBSD 16-CURRENT, agent 0.107.0). The
script beside this note,
[cblink-v2-frame-sizes.py](cblink-v2-frame-sizes.py), does the
encoding and the counting; this note gives its numbers and what they
say.

## What was measured

**Version 1** is what the agent sends today for `arcanactl net
interfaces` (cblink family `arcana`, command `network`, kind
`interfaces`): one reply whose body is the map `{10 (ok): true, 27
(json): "<JSON text>"}`, the JSON being what `do_interfaces()` builds
from getifaddrs(3): per interface its name, `up`, flags, link state,
MTU, MAC address, the six counters and its addresses, plus `carp` and
`time` at the top. The frame is the 24-byte header and that body.

**Version 2** is the same data, hand-encoded as YANG-CBOR (RFC 9254),
as Y-1 would send it:

- `ietf-interfaces` (RFC 8343): `name`, `type` (an identityref of
  `iana-if-type`: `ethernetCsmacd`, `softwareLoopback` or `other`),
  `enabled`, `oper-status`, `phys-address` and `statistics` with
  `in-octets`, `in-unicast-pkts`, `in-errors`, `out-octets`,
  `out-unicast-pkts`, `out-errors`, and the `discontinuity-time` the
  module makes mandatory in `statistics`;
- `ietf-ip` (RFC 8344): `ipv4` and `ipv6` with `mtu` and their
  `address` lists (`ip`, `prefix-length`);
- an Arcana augment: the interface flags as `bits` (a byte string,
  least significant bit first), and the reading's `time` at the top.

It is sent two ways: as **one reply**, `{interfaces: {interface:
[entries]}}`, like version 1; and as the **dump** the plan describes
for `GET` on a list, one frame per interface keyed `{[SID, name]:
entry}`, then a header-only `DONE`.

The SIDs are placed by block, since only each key's width changes the
size: top-level SIDs in the IANA blocks of RFC 9595 (ietf-interfaces
from 1500, ietf-ip from 1600, iana-if-type from 1800, `ethernetCsmacd`
being 1880 as in RFC 9254 §6.6), so each top-level key is 3 bytes;
siblings within a module within 23 of each other, so each nested key
is 1 byte; ietf-ip's containers a 1600-block augment under a 1500-block
list, 2 bytes; and Arcana's augment from the provisional block at 2^40,
where the cblink module's SIDs are, 9 bytes.

## The numbers

The VM's 9 interfaces (`vtnet0`, `lo0`, `pfsync0`, `enc0`, two epair
pairs, `vtnet1`), and the same reading grown to 200 interfaces by
repeating one epair entry, the size of a jail host:

| | 9 interfaces | 200 interfaces |
|---|---:|---:|
| v1 JSON text | 2 813 | 90 624 |
| **v1 reply** (header + `{ok, json}`) | **2 845** | **90 658** |
| **v2 reply** (one frame) | **1 237** (43 %) | **39 226** (43 %) |
| **v2 dump** (a frame per interface, then `DONE`) | **1 540** (54 %) | **46 784** (52 %) |
| v2 dump frames | 10, of 102 to 271 bytes | 201, of 232 to 234 bytes |
| of v2: Arcana's augment at 2^40, over a 2-byte key | 63 | 1 400 |
| of v2: `discontinuity-time`, which v1 does not send | 252 | 5 600 |

## What they say

- **Version 2 is under half of version 1 on the wire**, 43 % as one
  reply, a little over half as a dump: the JSON's quoted names and
  decimal counters become one-byte keys and binary integers. The
  saving holds as the host grows; it is per interface, not a fixed
  overhead.
- **The dump costs a fifth to a quarter more than one reply** (the 24-byte
  header and the `[SID, name]` key on every frame), and in exchange a
  receiver handles one interface at a time and the 1 MiB `max_frame`
  never bounds the table: version 1's single reply of a 200-interface
  host is already 9 % of it, and the agent refuses a reply past 4 MiB
  of JSON.
- **The block a module's SIDs come from matters.** (Since 2026-10-14
  Arcana's and cblink's SIDs are in RFC 9595's experimental range,
  60 000 to 99 999: such a key is 3 bytes, and the figures here for
  the 2^40 block are those of its day.) A key into the 2^40
  block is 9 bytes; Arcana's one augmented leaf per interface costs 7
  bytes over a near one, 3 to 4 % of the dump. Every Arcana augment of an
  IETF list pays it per entry. When the SID mega-range is asked for
  (step 0.5.1), a block below 2^32 makes such keys 5 bytes, and an
  Arcana module's own top-level SIDs too; the cblink module's
  structures, keyed at the top of every error, credit and close frame,
  would gain the same.
- **`discontinuity-time` is the largest single cost of following the
  model**: 28 bytes an interface, 14 to 20 % of the v2 reply, for a value
  FreeBSD keeps nowhere (`if_data` has no counter-reset time; the
  agent's start or the interface's creation would stand for it). A
  deviation `not-supported` would save it but is not standard practice
  for a mandatory leaf; the plan's deviations (Y-2) decide.
- **Nothing in the frame header changes**: 24 bytes in both versions.
  A control frame with nothing but framework data grows: an `S_CREDIT`
  granting 128 KiB is 31 bytes in version 1 (`{-6: 131072}`) and 41 in
  version 2 (`{credit: {increment: 131072}}`, the structure's SID 2^40
  + 31 a 9-byte key, then its own map and a 1-byte delta); 37 with the
  cblink module below 2^32.

## Also seen

`vtnet1` came back from the agent twice over: getifaddrs(3) returned
two link entries by that name, `do_interfaces()` found the interface's
object by name and inserted each key again, and libucl made each such
key an implicit array, so the JSON says `"up": [false, false]`,
`"mtu": [1500, 1500]` where a scalar belongs. The counts above take the
first value. That is a fault of version 1 to fix on its own, outside
this step; a strict reader (the Android app) would reject the shape.
