#!/usr/bin/env python3
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
#
# Frame sizes of an interfaces read, wire version 1 against a hand-encoded
# version 2 (PLAN-SDN-YANG, step 0.1.4; the results are in
# cblink-v2-frame-sizes.md beside this file).
#
#	arcanactl -c URI net interfaces > if.json
#	python3 cblink-v2-frame-sizes.py if.json
#
# Version 1 is what the agent sends today: one reply whose body is
# {10 (ok): true, 27 (json): "<the JSON text>"}.  Version 2 is the same
# data as YANG-CBOR (RFC 9254) of ietf-interfaces, ietf-ip and an Arcana
# augment, sent two ways: one reply, or a dump of one frame per interface
# keyed [SID, name] and a header-only DONE.
#
# SIDs: only the width of each key matters to the sizes.  Top-level SIDs
# sit in the IANA blocks of RFC 9595 (ietf-interfaces 1500, ietf-ip 1600,
# iana-if-type 1800; ethernetCsmacd is 1880, RFC 9254 section 6.6);
# within a module, siblings are near each other (a delta of one byte);
# ietf-ip's containers are a 1600-block augment of a 1500-block list (two
# bytes); Arcana's augments come from its provisional block at 2^40, the
# block of the cblink module (nine bytes).

import json
import struct
import sys

HDRLEN = 24


def head(major, n):
    if n < 24:
        return bytes([major << 5 | n])
    if n < 0x100:
        return bytes([major << 5 | 24, n])
    if n < 0x10000:
        return bytes([major << 5 | 25]) + struct.pack(">H", n)
    if n < 0x100000000:
        return bytes([major << 5 | 26]) + struct.pack(">I", n)
    return bytes([major << 5 | 27]) + struct.pack(">Q", n)


def enc(v):
    if v is True:
        return b"\xf5"
    if v is False:
        return b"\xf4"
    if isinstance(v, int):
        return head(0, v) if v >= 0 else head(1, -1 - v)
    if isinstance(v, str):
        b = v.encode()
        return head(3, len(b)) + b
    if isinstance(v, bytes):
        return head(2, len(v)) + v
    if isinstance(v, list):
        return head(4, len(v)) + b"".join(enc(e) for e in v)
    if isinstance(v, tuple):			# a map, as (key, value) pairs
        return head(5, len(v)) + b"".join(enc(k) + enc(x) for k, x in v)
    raise TypeError(v)


ARCANA = 1 << 40				# the provisional block

# ietf-interfaces (deltas from the list "interface" and from "statistics").
IF_LIST = 1533					# /if:interfaces/if:interface
IF_INTERFACES = IF_LIST - 1
D_DESCRIPTION, D_ENABLED, D_NAME, D_TYPE, D_OPER, D_PHYS, D_STATS = (
    1, 2, 4, 5, 11, 13, 20)
STATS = IF_LIST + D_STATS
D_DISC, D_IN_OCT, D_IN_UNI, D_IN_ERR, D_OUT_OCT, D_OUT_UNI, D_OUT_ERR = (
    1, 2, 3, 6, 9, 10, 13)
# ietf-ip, augmenting the interface from its own block.
IPV4, IPV6 = 1610, 1640
D_ADDR, D_MTU = 1, 4				# from ipv4 / ipv6
D_IP, D_PREFIX = 1, 3				# from an address entry
# iana-if-type identities.
ETHER, LOOPBACK, OTHER = 1880, 1824, 1801
# Arcana's own: the flags of an interface, the time of a reading.
AR_FLAGS = ARCANA + 60
AR_TIME = ARCANA + 61
FLAG_BITS = ["UP", "BROADCAST", "DEBUG", "LOOPBACK", "POINTOPOINT",
             "RUNNING", "NOARP", "PROMISC", "ALLMULTI", "SIMPLEX", "LINK0",
             "LINK1", "LINK2", "MULTICAST", "PPROMISC", "MONITOR",
             "STATICARP"]
OPER = {"up": 1, "down": 2, "unknown": 4}
# A date-and-time, mandatory in statistics (RFC 8343): its length only.
DISCONTINUITY = "2026-10-13T00:00:00+00:00"


def bits(flags):
    v = 0
    for f in flags:
        if f in FLAG_BITS:
            v |= 1 << FLAG_BITS.index(f)
    n = max(1, (v.bit_length() + 7) // 8)
    return v.to_bytes(n, "little")		# RFC 9254 6.7: LSB first


def iftype(name):
    if name.startswith(("vtnet", "em", "igb", "ix", "epair", "bridge")):
        return ETHER
    if name.startswith("lo"):
        return LOOPBACK
    return OTHER


def entry(i):
    """One interface entry, its keys deltas from the list's SID."""
    kv = [(D_NAME, i["name"])]
    if "description" in i:
        kv.append((D_DESCRIPTION, i["description"]))
    kv.append((D_TYPE, iftype(i["name"])))
    kv.append((D_ENABLED, bool(i.get("up"))))
    kv.append((D_OPER, OPER.get(i.get("link"), 4)))
    if "ether" in i:
        kv.append((D_PHYS, i["ether"]))
    if "ibytes" in i:
        kv.append((D_STATS, (
            (D_DISC, DISCONTINUITY),
            (D_IN_OCT, i["ibytes"]), (D_IN_UNI, i["ipackets"]),
            (D_IN_ERR, i["ierrors"]), (D_OUT_OCT, i["obytes"]),
            (D_OUT_UNI, i["opackets"]), (D_OUT_ERR, i["oerrors"]))))
    for fam, sid in (("inet", IPV4), ("inet6", IPV6)):
        addrs = [a for a in i.get("addresses", []) if a["family"] == fam]
        if not addrs:
            continue
        c = []
        if "mtu" in i:
            c.append((D_MTU, i["mtu"]))
        c.append((D_ADDR, [tuple([(D_IP, a["address"])] +
                                ([(D_PREFIX, a["prefixlen"])]
                                 if "prefixlen" in a else []))
                          for a in addrs]))
        kv.append((sid - IF_LIST, tuple(c)))
    if "flags" in i:
        kv.append((AR_FLAGS - IF_LIST, bits(i["flags"])))
    return tuple(sorted(kv))


def main():
    with open(sys.argv[1]) as f:
        doc = json.load(f)
    ifs = doc["interfaces"]
    # arcanactl folds a key the agent sent twice into an array: an
    # interface getifaddrs(3) gave twice is counted once.
    for i in ifs:
        for k, v in list(i.items()):
            if k not in ("addresses", "flags") and isinstance(v, list):
                i[k] = v[0]
    # Version 1: the agent's compact JSON inside one text attribute.
    text = json.dumps(doc, separators=(",", ":"))
    v1 = HDRLEN + len(enc(((10, True), (27, text))))
    # Version 2, one reply.
    body = (
        (IF_INTERFACES, ((IF_LIST - IF_INTERFACES, [entry(i) for i in ifs]),)),
    )
    if "time" in doc:
        body += ((AR_TIME, doc["time"]),)
    v2 = HDRLEN + len(enc(tuple(sorted(body))))
    # Version 2, a dump: {[SID, name]: entry} a frame, then DONE.
    frames = [HDRLEN + len(head(5, 1) + enc([IF_LIST, i["name"]]) +
                           enc(entry(i))) for i in ifs]
    dump = sum(frames) + HDRLEN
    print("interfaces\t%d" % len(ifs))
    print("v1 JSON text\t%d" % len(text))
    print("v1 reply\t%d" % v1)
    print("v2 reply\t%d\t%.0f%%" % (v2, 100.0 * v2 / v1))
    print("v2 dump\t%d\t%.0f%%\t(%d frames, %d..%d bytes)" % (
        dump, 100.0 * dump / v1, len(frames) + 1, min(frames), max(frames)))
    # Of the v2 reply, what Arcana's far augment costs in keys alone.
    far = sum(1 for i in ifs if "flags" in i) * (len(head(0, AR_FLAGS -
              IF_LIST)) - 2)
    print("v2 far-key cost\t%d\t(bytes over a 2-byte key)" % far)
    # And what statistics' mandatory discontinuity-time costs.
    disc = sum(1 for i in ifs if "ibytes" in i) * len(enc(D_DISC) +
                                                     enc(DISCONTINUITY))
    print("v2 discontinuity-time cost\t%d" % disc)


if __name__ == "__main__":
    main()
