# cblink as a strict YANG protocol — engineering analysis

Inputs: the 18 RFC/draft notes in this directory, /home/user/arcana/cblink/docs/*.md,
cblink sources (20.7k lines: libcblink 15.0k incl. 1.6k generated ctrl family, cblink-gen
5.1k, fuzz 0.2k), share/arcana/arcana.yaml (3044 lines: 430 named items, ~40 operations,
~30 attribute sets, 10 definitions), jobs.yaml (361 lines).

Goal restated: keep the 24-byte frame, mTLS/SCTP/AF_UNIX transports, seq correlation,
do/dump/notify/stream machinery and credit flow control; replace the YAML family
language, the per-set attribute ids and the ad-hoc policy vocabulary with YANG 1.1
modules, RFC 9595 SIDs and RFC 9254 YANG-CBOR; make the agent an NMDA datastore server
with CORECONF-shaped operations, YANG-Push subscriptions and NACM; make the console a
RESTCONF (JSON) server in front of a fleet of cblink agents.

Every section ends with a decision proposal marked **D-n**.

---------------------------------------------------------------------------------------

## (a) Wire: YANG-CBOR with SID deltas inside a cblink body

### a.1 What RFC 9254 requires versus what cblink v1 forbids

| RFC 9254 rule | cblink v1 rule | Conflict? |
|---|---|---|
| Map keys are SID deltas: signed integers, relative to the parent schema node's SID (reference 0 at the outermost map and after a name key; rpc/action children relative to the rpc/action SID; list entries relative to the list SID) | Positive keys 1..65535 = family attributes defined per attribute set; 0 and >65535 ignored; −1..−64 framework; <−64 reserved-ignored | Yes, twice: deltas can be negative (an augmenting module with a lower SID block, rpc `output` nodes, `input`/`output` themselves are SIDs below their children; e.g. `v4ur:destination-prefix` under `rt:route`, or `ni:bind-ni-name` under `if:interface`) and deltas can exceed 65535 (cross-module augments when modules live in different mega-ranges). A negative delta in −1..−64 would be read as a framework attribute. |
| Top-level keys are absolute SIDs (63-bit) | ≤ 65535 | Absolute SIDs for IETF modules are 1000..299999, Arcana's will be ≥ 2^20 |
| Tag 47 (absolute SID), tags 43/44/45/46 (bits/enumeration/identityref/instance-identifier inside unions), tag 4 (decimal64 as decimal fraction) | Tags MUST NOT be sent | Yes |
| Indefinite-length "SHALL be supported" — but §3: a protocol using YANG-CBOR MAY restrict; CORECONF does | Rejected | No (declare the restriction, as CORECONF does) |
| `empty` = `null`; `boolean` = true/false; no `undefined` | Only true/false/null simple values | No |
| Floats are never produced by YANG types (decimal64 is tag 4) | Floats accepted | Harmless; may drop |
| Unknown SIDs: an implementation may reject or ignore (9254 §4.1.2: "SHOULD be ignored" is *not* said; CORECONF treats an unknown SID as `invalid-value`); NETCONF/RESTCONF: `unknown-element` | Unknown attributes ignored | Policy change: ignore on read of *operational* data from a newer peer (forward compatibility), reject in edits (an unknown node in a config write is an error in every YANG protocol) |
| Duplicate keys forbidden, text UTF-8 | Same | No |
| Preferred (shortest) integer encoding | SHOULD | No |

### a.2 Options for carrying framework attributes

**Option 1 — framework map wrapper.** Body = cblink map as today; the YANG-CBOR item is
the value of one positive key, e.g. `{1: <yang-cbor map>, -1: CODE, -2: MSG, ...}`. The
cblink attribute layer keeps its key rules for the outer map only; the inner item is kind
`any` and handed to the YANG layer, which applies delta semantics. Nested negative deltas
never meet the outer rules.
Cost: 2 bytes per frame (map header + key); the "policy" machinery of cblink cannot validate
the inner item (fine: the YANG validator does); two decoders in series.
Risk: none; purely additive; could even be shipped as wire version 1 (a new family uses key 1
for the whole YANG item) — nothing in v1 forbids a nested map with negative keys inside a
family attribute (section 5.3 says nested maps follow "the same key rules", so strictly a
v1 receiver must reject negative keys in nested maps; a kind `any` value escapes that).

**Option 2 — distinct top-level key space = absolute SIDs.** Body = exactly one YANG-CBOR
map whose top-level keys are absolute SIDs (always ≥ 1, unsigned). Framework data becomes
YANG too: a module `cblink` defines `sx:structure` items (RFC 8791) — `error`
(reuse `ietf-coreconf`'s `error` structure SID 1024 with error-tag identities 1001..1023,
augmented by `cblink` with `errno` and `cookie`), `credit {increment}`, `hello {limits…}`,
`close {code, message}`, `notification {event-time, anydata event}`, `warning`. A frame body
is then `{ SID: value, ... }` where every top-level SID identifies either a data node /
rpc / structure of some module. Negative numbers appear only as nested deltas, where the
schema, not a key-range rule, says what they mean. The decoder dispatches on the top-level
SID: cblink structures are handled by libcblink; everything else goes to the generated
schema tables. `MISS_TYPE` becomes `error-tag missing-element` + `error-data-node`;
`PATH` becomes `error-data-node` (an instance-identifier: SID or [SID, keys...]) — the same
array shape PATH has today.
Cost: top-level keys are 2–5 bytes instead of 1 (SID 1024 = 3 bytes); an `S_CREDIT` frame
grows from 28 to ~31 bytes. Nested keys stay 1 byte for deltas in −24..23 (siblings in one
module are consecutive, so most deltas are small).
Risk: wire version 2 (header `version` field exists for this). The strict-CBOR profile is
kept except tags 4, 43–47.

**Option 3 — header.** Move fixed-width framework fields into a longer header (`hdrlen`
is already a field): `code` u32, `credit` u32, `miss`→SID u64. Variable-length fields
(`MSG`, `PATH`, `COOKIE`) still need the body, so the header alone cannot carry the
framework; it would be Option 2 plus a bigger header for the two fields that appear in
control frames with no other body (`S_CREDIT`, header-only `ERROR`). Saves 3–7 bytes on
those frames only; makes the header 32 or 40 bytes for every frame. Not worth it.

**Option 4 — CBOR sequence body.** Body = framework map (cblink v1 negative keys) followed
by an optional YANG-CBOR item (RFC 8742 sequence). Keeps v1 framework encoding bit-exact;
costs nothing when there is no framework data (sequence of one item). But "exactly one
data item" is cblink's simplest invariant and the length-prefix-before-allocation property
holds either way; two decoders again.

**D-1: Option 2.** Body = one YANG-CBOR map with absolute SIDs at the top level; framework
items are `sx:structure`s of module `cblink` with SIDs in Arcana's block; the frame
`version` becomes 2; tags 4 and 43–47 are allowed and all others rejected; indefinite
lengths stay forbidden (as in CORECONF); `undefined` stays forbidden. The decoder keeps
the single-pass, size-before-allocation behaviour because YANG-CBOR uses definite lengths.
Option 1 is the fallback if v1 compatibility on the wire must be kept during the
transition (both can coexist: version 1 frames = legacy families, version 2 = YANG).

### a.3 Type mapping (cblink kinds → YANG-CBOR)

| cblink kind | YANG type(s) | 9254 encoding | Change in libcblink |
|---|---|---|---|
| uint | uint8/16/32/64, enumeration (value), identityref (SID) | major 0 | enum: value table from schema; identityref: SID + derivation check |
| int | int8/16/32/64 | major 0/1 | none |
| bool | boolean | true/false | none |
| flag (true = present) | empty | **null** | kind `empty`; wire changes from F5 to F6 |
| text | string, and strings carrying patterns (inet types, date-and-time) | major 3 | pattern + length checks |
| bytes | binary | major 2 | none |
| float | — (decimal64 is tag 4 [exp, mantissa]) | tag 4 | kind `decimal64`; drop float or keep as extension |
| nest | container, list entry, anydata | map | delta-keyed children |
| multi (array) | leaf-list, list | array | list = array of maps (ordered-by user preserved) |
| any | anyxml / anydata | any | unchanged |
| enum/flags definitions | enumeration / bits | enumeration = uint; **bits = byte string, LSB-first, or array for sparse** | bits encoder/decoder (cblink `flags` is a uint mask → wire change) |
| — | union | member encoding; tags 43–46 disambiguate bits/enum/identityref/instance-id | new |
| — | instance-identifier | SID (uint) or [SID, key...] array; tag 47 in some contexts | new; equals today's PATH |
| — | leafref | target type | validator |
| — | decimal64 | tag 4 | new |

Sizes: for `ietf-interfaces` an `interface` entry has children deltas 1..14 (1 byte each),
the list `interface` under `interfaces` delta 1, top-level `interfaces` SID 1500 (3 bytes).
A dumped entry is within a byte or two of today's `{1: name, 2: ...}` encoding.
Statistics counters as uint64 are the same in both.

### a.4 Decoding cost and policy tables

Today: `cbl_policy` arrays indexed by key 1..N per attribute set. With deltas the children
of a schema node are a sorted `int64 delta → node` table (binary search, ≤ 30 children
typically) or a dense array when deltas are contiguous (the common case for a single
module — generator chooses per node). Decoder depth is bounded as today (`max_depth`).
Limits (max frame, max text) unchanged.

---------------------------------------------------------------------------------------

## (b) Operations: datastore access, rpc/action/notification on do/dump/notify/stream

### b.1 Shape of the YANG protocol family

Keep the header's `family` as a protocol multiplexer, not a module id: `0` = control
(as today, re-expressed in YANG), `1` = `cblink-yang` datastore protocol; legacy numeric
families stay valid for transition and die with "numbers are forever" (never reused).
`cmd` within family 1 is a small fixed operation set (the "method"), the *content* says
which module/node is touched — like CORECONF where the method is CoAP's and the resource
is the SID.

| Semantic | NETCONF (6241/8526) | RESTCONF (8040) | CORECONF (comi-21) | cblink v2 (family 1) |
|---|---|---|---|---|
| read one node / subtree | `<get-data>` with `xpath-filter`/`subtree-filter`, `with-defaults`, `max-depth`, `with-origin` | `GET /data/...` + `content`, `depth`, `fields`, `with-defaults` | FETCH `yang-identifiers` (CBOR seq of instance-ids) → `yang-instances`; GET whole datastore | `cmd GET` do: body `{cblink:get: {datastore (identityref ds:*), targets* instance-identifier, depth, with-defaults, with-origin, fields?}}` → reply `{SID|[SID,keys]: value, ...}`; for a list or many targets use **dump**: one MULTI frame per instance `{[SID,keys]: entry}` then DONE — this is exactly CORECONF's `yang-instances` CBOR sequence spread over frames |
| read config only | `<get-config>` running | `GET ...?content=config` | GET/FETCH on `running` (unified datastore in CORECONF) | same with `datastore = ds:running` |
| merge | `edit-config` default-operation merge | `PATCH` (plain) | iPATCH `{instance-id: value}` | `cmd EDIT` do, body = YANG Patch (RFC 8072 `yang-patch` structure: `edit*[edit-id]{operation, target, point, where, value}`) encoded in CBOR; `operation` ∈ create/delete/insert/merge/move/replace/remove; `target` is an instance-identifier (SID form), not an api-path string — a cblink deviation of `target-resource-offset`? No: define `cblink:edit` structure with the same fields but `instance-identifier` targets; convert to/from RFC 8072 at the console |
| replace / create / delete / remove | `edit-config` operation attrs | `PUT` / `POST` / `DELETE` | PUT / iPATCH with `null` / DELETE | same EDIT with per-edit operation; the RESTCONF/CORECONF single-op forms are 1-edit patches |
| whole datastore replace | `copy-config` | `PUT /data` | PUT `/c` | `cmd EDIT` with one `replace` whose target is the datastore root (instance-id `/`) |
| candidate / commit / confirmed-commit / discard | `commit`, `cancel-commit`, `discard-changes` | none (RESTCONF has no candidate; `confirmed-commit` absent) | none | `cmd RPC` invoking `ietf-netconf`-style rpcs defined in `cblink-datastore` (commit {confirmed, timeout, persist}, cancel-commit, discard-changes); candidate is optional (feature `candidate`) |
| lock | `lock`/`unlock` | none | none | optional, connection-scoped `lock {datastore}`; auto-released on close (like NETCONF) |
| rpc | `<rpc><x:op>` | `POST /operations/x:op` | POST `{SID: input}` | `cmd RPC` do: `{SID(rpc): {input deltas}}` → `{SID(rpc): {output deltas}}` or empty ACK |
| action on a list entry | `<action>` with the data node path | `POST /data/.../list=k/action` | POST `{[SID(action), keys...]: input}` | same as rpc with an instance-identifier key: `{[SID(action), k1, k2]: {input}}` |
| notification (event stream) | `<notification><eventTime>` | SSE `{"ietf-restconf:notification": {eventTime, x:notif}}` | Observe on `/s` returning `{SID(notif): content}` (no eventTime in comi-21!) | NOTIFY frame body `{SID(cblink:notification): {event-time, event: <anydata {SID(notif): {...}}>}}` with `stream` = subscription-id (see b.3) or S_DATA on a push stream |
| subscription | 8639/8641 rpcs | same + SSE | Observe | `establish-subscription` as a **push-stream open** (b.3) |
| errors | `rpc-error` {error-type, error-tag, error-severity, error-app-tag, error-path, error-message, error-info} | `yang-errors` structure + HTTP status | `error` structure SID 1024: error-tag identityref, error-app-tag, error-data-node, error-message | ERROR frame body `{1024: {error-tag, error-app-tag, error-data-node, error-message, cblink:errno, cblink:cookie}}` — CODE (errno) is preserved as an augment-structure leaf, so FreeBSD-errno semantics survive; `error-tag` gives the RFC 8040 §7 HTTP status mapping for free at the console |
| capability discovery | `<hello>` capabilities, yang-library | `/yang-library-version`, `ietf-yang-library` | `/c/<SID of yang-library>` | `ctrl hello` → `{cblink:hello: {limits, yang-library-content-id}}`; `ietf-yang-library:yang-library` readable via GET; **plus** `cmd GET-SID` returning the `ietf-sid-file` structure for a module, so a generic client can decode what the agent speaks |

Mapping to the existing Arcana family: `hello`→hello+yang-library; `list`(jails)→GET/dump
of `arcana-jails:jails/jail`; `action`(jail start/stop)→actions on the jail list entry;
`address live/persistent`→EDIT on `arcana:live` dynamic datastore vs `running`;
`services`/`service-action`/`service-config`→`arcana-services` list + actions +
rc.conf variables as leaves; `network`→`ietf-interfaces`/`ietf-ip`/`ietf-routing`
operational; `stats`→operational containers (and YANG-Push periodic); `packages`,
`pkg-upgrade`→list + rpc with a job; `job-submit/jobs/job/job-cancel/job-confirm`→
`arcana-jobs:jobs/job[id]` list, rpc `submit` (output job-id), actions `cancel`/`confirm`,
trace stream → YANG-Push on-change subscription to the job's `steps` list or a dedicated
`arcana-jobs:trace` notification stream filtered by job-id; `agent-update/agent-build/
console-update`→rpcs; `route-lookup`→`rt:active-route` action; `bird-config`→
`arcana-routing:bird` config container (and FRR later); `kernel`, `storage`, `fstab`,
`transport`, `sysctl`→Arcana modules (`sysctl` is a natural list `sysctl[name]{value}`
with `config true` entries persisted to sysctl.conf and operational values from `sysctl(3)`).

### b.2 Datastores (RFC 8342) on FreeBSD

| Datastore | Backing | Notes |
|---|---|---|
| `running` | rc.conf (+ rc.conf.d/*), jail.conf, loader.conf, sysctl.conf, rtadvd.conf, pf.conf (text) | read-modify-write preserving comments and ordering (Arcana already edits rc.conf and has libjailconf); origin `intended` |
| `intended` | = running (no templates/inactive) | 8342 allows them equal |
| `candidate` (feature) | agent-side copy of running (in-memory tree + rendered files in a staging dir) | commit = write files + apply; confirmed commit with timeout = Arcana's job-confirm safety for remote network changes |
| `startup` | absent (FreeBSD has no separate startup store; rc.conf *is* startup) | advertise `:startup` absent |
| `arcana:live` (dynamic configuration datastore, 8342 §5.2) | kernel-only changes (ifconfig/route/sysctl without persistence) | writes apply immediately, never persist; origin `dynamic` in operational; this is today's `address live` |
| `operational` | kernel: ioctl/sysctl/rtsock/netlink/jail_get, services' status, pkg db | may violate constraints (8342 §5.3: `link-layer-address` absent while `incomplete`); `with-origin` supported: intended/system/dynamic/learned/default/unknown |

Edit semantics (NETCONF §7.2 + 8072): `merge` (default), `replace`, `create` (EEXIST →
`data-exists`), `delete` (ENOENT → `data-missing`), `remove`, `insert`/`move` for
ordered-by user lists (`point`, `where`). Validation runs on the resulting tree (7950 §8.1)
before anything is written; apply = render files + apply to kernel; failure in apply
after files were written → rollback (restore previous file copies) and
`operation-failed`; `error-option` rollback-on-error is the only mode.

### b.3 Subscriptions on cblink streams

- `establish-subscription` (8639) = open a **push stream** (op flag `CBL_OPF_PUSH`): the
  `S_OPEN` request body carries the rpc input `{SID(establish-subscription): {stream|
  datastore, filter, period|on-change, ...}}`; the accept frame carries the rpc output
  `{id, replay-start-time-revision}`; event records and subscription-state notifications
  then flow as `S_DATA` frames `{SID(cblink:notification): {event-time, event}}` in order
  with credit; `S_HCLOSE` from the publisher = `subscription-completed` (stop-time);
  `S_CLOSE` from the subscriber = `delete-subscription`; `S_RESET` from the publisher =
  `subscription-terminated` with the reason in the error structure. Credit exhaustion:
  the publisher emits `subscription-suspended {unsupportable-volume}` when it must drop,
  `subscription-resumed` when credit returns (8639 §2.4.3 behaviour implemented by the
  transport's own flow control — this is a better fit than NOTIFY's best-effort drop + `ENOBUFS` marker).
- `modify-subscription`, `kill-subscription`, `resync-subscription` = ordinary rpcs
  referring to the id; the id ↔ stream-id mapping lives in the connection.
- Configured subscriptions (feature `configured`): the agent as publisher calling home to
  the console (transport identity `cblink:cblink`, receiver augmentation `address`, `port`,
  `tls-client-cert`); valuable because the console then survives restarts and the agent
  keeps state — matches today's enrolment/reconnect machinery.
- cblink multicast groups + `NOTIFY` frames remain as the "no subscription state, no
  replay" fast path (e.g. the control family's own notifications and the `NETCONF`-like
  default stream for local AF_UNIX clients); `stream` field = subscription id.
- Event time: cblink defines `sx:structure notification { leaf event-time date-and-time;
  anydata event; }` (8040 §6.4 shape, which CORECONF lacks).

### b.4 Dump and large results

`GET` of a list or of many targets uses dump (MULTI + DONE), one instance per frame, each
frame self-contained (`{[SID, keys]: entry}`) so the console can stream NDJSON/SSE or
assemble. RESTCONF `depth`/`fields` map onto the agent's `fields` (a subtree-filter-like
anydata in `cblink:get`) — the agent filters, not the console.

**D-2:** family 1 = `cblink-yang` with cmds GET (do/dump), EDIT (do), RPC (do/stream for
push-type rpcs), GET-SID (do); subscriptions on push streams; errors as `ietf-coreconf:error`
+ cblink augment; NMDA datastores running/candidate(opt)/operational + `arcana:live`.

---------------------------------------------------------------------------------------

## (c) Generator: own YANG parser in C versus pyang plugin versus libyang at build time

### c.1 What the generator must understand

Syntax (7950 §14 ABNF): ~70 statements, three string forms (unquoted, single, double with
escapes and indentation stripping, `+` concatenation), `yang-version 1` and `1.1`
(ietf-netconf-acm is 1.0), comments, extension statements with arbitrary bodies, submodules
(`belongs-to`, `include`, revision-date). Lexer+parser: ~1.5k lines; small risk.

Semantics (the real cost): module/import/prefix resolution with revisions; typedef chains
with restriction inheritance (range/length narrowing, pattern accumulation, `modifier
invert-match`, fraction-digits, enum/bits in restricted types, union members, leafref paths,
`require-instance`, defaults inherited from typedefs); groupings/uses with `refine` and
uses-scoped `augment` (ietf-ipv4-unicast-routing uses that); `augment` with relative/absolute
schema node ids targeting containers, lists, choices, cases, rpc input/output,
notifications, including cases implicitly created (shorthand), `when` on augments; `choice`/
`case` shorthand, `default` case; `deviation` (not-supported, add, replace, delete);
`feature`/`if-feature` boolean expressions (1.1) and feature pruning at generation time;
identities with multiple bases; `config` inheritance and the rule that config true must not
be under config false; `mandatory` semantics (7950 §3); `status`; `ordered-by`; `unique`;
`key` with `leafref` keys not allowed? (keys may be leafref of other types); `action`,
`notification` inside data (1.1); `anydata`/`anyxml`; XPath *parsing* for must/when/path
(the validator needs the AST, and the generator should reject expressions outside the
supported subset at build time); extension recognition: `sx:structure`/`augment-structure`,
`rc:yang-data`, `yangmnt:mount-point`, `nacm:default-deny-*`, `sn:subscription-state-
notification`; module update rules are not the generator's job but SID stability is.
Estimated: schema model + resolution 4–5k lines, type system 2k, XPath parser 1.2k,
feature/deviation 0.6k, extension hooks 0.4k, diagnostics 0.5k.

Patterns: YANG uses XSD regular expressions (W3C XML Schema Part 2 §F): `\d \w \s \p{L}`,
character-class subtraction `[a-z-[aeiou]]`, no anchors (implicitly anchored), no
backreferences. FreeBSD base has POSIX `regex(3)` (ERE) only. Options: translate the XSD
subset used by IETF modules (`\d`, `\s`, `\w`, `\.`, `\p{N}`/`\p{L}` → classes, `[^…]`,
`{n,m}`, `|`, `()`, `?*+`) into ERE at generation time (~400 lines; fails loudly on
unsupported constructs) and compile with `regcomp` at runtime (REG_EXTENDED, anchored by
wrapping `^(...)$`); or a small backtracking matcher for the XSD syntax (~900 lines, exact).
The translation approach covers ietf-inet-types, ietf-yang-types, iana-*, 8343/8344/8349
(all their patterns are simple); keep a generation-time `pattern-check` test that runs the
RFC 6991 patterns against known good/bad values.

SID files: JSON (`ietf-sid-file` structure, RFC 9595 §6); base has `libucl` (used by pkg
and by Arcana's console), which parses JSON → no new dependency. The generator reads the
`.sid` files of all modules, verifies items ↔ schema (missing items → assign the next free
SID in the module's range, RFC 9595 §6 ordering; obsolete items keep their numbers; a
schema item without a SID = build error unless `--assign`), writes updated `.sid` files
(the ledger), and emits SID tables. ~1.2k lines.

C emission: structs per container/list/rpc input/output/notification/structure with
`has_` flags, arrays for leaf-lists/lists, union variants, `cbl_bytes` for binary/bits;
schema tables (node kind, delta, type, constraints, children, keys, when/must expression
ids, default values, config, mandatory, min/max-elements, ordered-by, identity table,
feature table, SID table); builders/parsers as today; datastore handler stubs (`get`,
`edit` callbacks per top-level container or per list), rpc/action handler prototypes,
notification send helpers, subscription helpers, markdown + tree diagrams (RFC 8340).
Replaces gen_c.c (1.85k) with ~5–6k.

### c.2 Three ways to get the semantics

| | Own C parser/compiler in cblink-gen | pyang plugin → intermediate (YAML/JSON) → cblink-gen | libyang2 linked into cblink-gen (build time only) |
|---|---|---|---|
| New code | 12–15k lines C | ~1.2k lines Python + ~1.5k C (intermediate reader) + emitter 5–6k | ~2.5k lines C glue (`lys_parse_*`, walk `lysc_node`, `lysc_type` with resolved ranges/patterns/enums, `lysc_when`/`lysc_must` already parsed; `lyd_*` for .sid? no — own SID code) + emitter 5–6k |
| Correctness | risk in augment/uses/refine/deviation/type-restriction corners; mitigated by a test corpus and cross-checking tree output against `pyang -f tree` in CI | pyang is the reference implementation; mature | libyang is the reference C implementation (used by sysrepo, FRR, netopeer); very mature |
| Build dependencies | none (base: cc, libucl, regex) | `lang/python3` + `pyang` from ports/pip at build time | `net/libyang` (ports; depends on `pcre2`) at build time; runtime none |
| Runtime dependencies | none | none | none |
| XPath parser | must write (needed anyway for the runtime evaluator — can share) | pyang gives expressions as strings; still must parse in C | libyang exposes compiled XPath internals only partially; still parse in C for the runtime |
| SID generation | own (RFC 9595 §6) | pyang `--sid-*` plugin exists (reference) | libyang has no SID support (it has `yanglint`-level CBOR? no) → own |
| Time | 10–14 weeks for parser+compiler | 3 weeks | 3–4 weeks |
| Strategic | self-contained FreeBSD-base-style toolchain; the generator can also serve as a `yanglint`-lite for Arcana modules | Python in the build; intermediate format becomes a second schema language to maintain (what GENERATOR.md is today) | pcre2+libyang in the build only; FreeBSD src policy would not accept it for a base tool, Arcana as a package can |

What "with base libraries only" buys: a user building Arcana from source needs only a
FreeBSD toolchain; the generated C is checked in, so even with option 2/3 the *consumer*
build needs nothing. The question is only what Arcana's own developers run. Since the
generated files are committed (as cbl_ctrl_gen.c is today), build-time Python or libyang
would be a developer dependency, not a user one.

**D-3:** Write the parser/compiler in C (option 1), bounded by a strict profile: reject
anything outside the profile at generation time (no `deviate replace` of types? keep;
no `anyxml` instance validation; XPath-lite only; XSD regex subset), and run
`pyang -f tree`/`yanglint` cross-checks in CI (developer tooling, optional). Rationale:
the runtime validator needs the same schema model and XPath parser in C anyway (≈ 60 % of
the work is shared), the module corpus Arcana needs is bounded (IETF: yang-types,
inet-types, interfaces, ip, routing+v4ur+v6ur, network-instance, logical-network-element,
yang-library, datastores, origin, schema-mount, netconf-acm, subscribed-notifications,
yang-push, yang-patch, restconf, coreconf, sid-file, yang-structure-ext, iana-if-type,
system; plus Arcana's), and a C compiler for YANG fits the cblink philosophy. If schedule
pressure dominates, option 3 (libyang at build time) delivers the same emitter 8–10 weeks
earlier and can be swapped later since the emitter consumes an internal schema model.

---------------------------------------------------------------------------------------

## (d) Validation: static tables versus runtime evaluation

### d.1 Classification of 7950 constraints

Static — expressible as per-node table entries checked by a generic engine while decoding
(this is today's `cbl_policy` grown up):
- kind/type match per 9254; integer `range` (list of inclusive sub-ranges, int64/uint64,
  also decimal64 with fraction-digits); string `length` (in characters, not bytes — count
  UTF-8 code points); `pattern` (+ `invert-match`) compiled at generator time; `enumeration`
  values; `bits` positions and length; `identityref` must be derived from the base(s) —
  identity table closure (generated, with union-of-bases); `union`: try members in order;
  `empty` = null only; `boolean`; `binary` with length; `instance-identifier` syntax (SID
  known, keys count); `leafref` *type* check (the target's type), existence deferred.
- structural: `mandatory` leaves/choices/anydata, `min-elements`/`max-elements`, presence
  of list `key` leaves, key uniqueness within a list instance, `unique` within a list
  instance (needs the whole list — still local), `config false` nodes in an edit →
  `invalid-value`, `choice` exclusivity, `ordered-by user` insert semantics, `default`
  materialisation (for `with-defaults` and for `when` evaluation on defaults), `status
  obsolete` rejected, `if-feature`-pruned nodes absent, `anydata` contents validated only
  if the schema is known (CORECONF: validate as the mounted/structure schema when the
  anydata is a `notification`/`datastore-contents`).
- These need the whole data tree only for list/unique scope; the engine can validate while
  building the tree, cost O(n log n).
- Generated table size: ~48 bytes per schema node + constraint blobs; Arcana + the IETF
  set ≈ 3,000 nodes → ~200 KB static data (acceptable; today's policies are similar per
  attribute).

Runtime evaluator (needs the data tree and XPath):
- `when` (node existence conditional; a false `when` makes present nodes invalid and
  suppresses defaults; evaluated with the node's parent as context; also on `augment`
  and `uses`).
- `must` (boolean; context = the node; error-message/error-app-tag from the statement).
- `leafref` existence (`require-instance true` default) — resolve the `path` with
  `current()` and `deref()`.
- `instance-identifier` existence (`require-instance`).
- `unique` across list entries (table-based, but with descendant schema node ids).
- Filters: subtree filter (structural, no XPath), XPath filters for subscriptions, NACM
  `node-instance-identifier` matching (instance-identifier with optional predicates and
  `$USER` — a tiny path matcher, not XPath).
- Schema-mount `parent-reference` node-set evaluation.
- `derived-from()` / `derived-from-or-self()` on identityrefs (used by every `when` in
  ietf-routing, sn, yp).

### d.2 How much XPath

Inventory of expressions in the target modules (from the notes): ietf-routing 1 `when`
(`derived-from-or-self(../type, 'rt:static')`); v4ur/v6ur 7+7 `when derived-from-or-self(
../../rt:address-family, ...)` at depths `../../` to `../../../../../`; RA submodule 2
`must` with arithmetic (`. <= 0.75 * ../max-rtr-adv-interval`, `. <= ../valid-lifetime`);
sn: `when` on encoding/transport with `derived-from`, `not(...)`; yp: `when` on
update-trigger/choice; yang-library: none; nacm: none; schema-mount: none; ni/lne: leafrefs
with simple paths; interfaces/ip: leafref `interface-ref`, examples use `must` with a
predicate `[if:name = current()]`; arcana modules: whatever we write (keep simple).
Needed subset ("XPath-lite"): location paths with `child`, `parent (..)`, `self (.)`,
`descendant-or-self` (`//`, rarely), predicates `[name = expr]` and `[pos]`? (no positional
predicates), `current()`, `deref()`, `derived-from()`, `derived-from-or-self()`,
`enum-value()`, `bit-is-set()`, `re-match()`, `count()`, `not()`, `boolean()`,
`string()`, `number()`, `concat()`, `contains()`, `starts-with()`, `string-length()`,
`substring()`, `normalize-space()`, `translate()`?, `name()`/`local-name()`/
`namespace-uri()` (parent-reference example), comparisons with node-set existential
semantics and numeric/string coercion, `and`/`or`, arithmetic `+ - * div mod` with
IEEE double (XPath numbers are doubles), union `|`, literals, variables (`$USER` for NACM
only). Excluded: `preceding`/`following`/`ancestor` axes beyond `..`, `position()`/
`last()`, `id()`, `lang()`. Size: parser 1.2k + evaluator 2.5–3k lines. The generator
rejects any expression outside the subset (and the agent rejects client-supplied filters
outside it with `filter-unsupported`), so the runtime never meets what it cannot evaluate.
libyang's full XPath is ~9.5k lines for comparison.

### d.3 Where validation runs

- Edits of `running`/`candidate`/`arcana:live`: full validation (types, structure, when,
  must, leafref, unique) on the *resulting* tree before applying; errors as
  `ietf-coreconf:error` with `error-data-node`.
- rpc/action input: types + structure + when/must inside the input tree (with the data
  tree accessible for leafrefs into config); output validated in debug builds.
- Operational reads: no constraint validation (8342 §5.3), types still enforced by the
  encoder; the console trusts the agent.
- Notifications: generated by the agent; types enforced by builders; debug-mode full check.
- Client-side (console, PWA via wasm): decoding + type validation of what the agent sent
  (defensive), never `must`/`when`.

**D-4:** static table engine in libcblink (rewrite of cbl_policy/cbl_attr/cbl_decode into a
schema-tree-driven validator producing an instance tree), plus a separate `cbl_xpath`
XPath-lite evaluator over that tree, with generation-time rejection of unsupported
expressions. Pattern checking via XSD→ERE translation + `regcomp`.

---------------------------------------------------------------------------------------

## (e) Console: RESTCONF north-bound over Kore, YANG-Push over SSE

What the Kore module must implement (from rfc8040.md):
- Discovery: `GET /.well-known/host-meta` (XRD, `rel="restconf"`), `{+restconf}` root
  (`/restconf`), `GET {+restconf}` → `ietf-restconf:restconf {data, operations,
  yang-library-version}`, `GET /yang-library-version` → `"2019-01-04"`.
- `/data`: api-path parsing (percent-decoding, `module:node` qualification at module
  boundaries, `list=k1,k2` with `,` and `%2C` escapes, leaf-list `=value`, empty key
  `=,` ), methods OPTIONS/HEAD/GET/POST/PUT/PATCH/DELETE with the status table (201 Created
  + Location, 204 No Content, 409 for data-exists, 404 for missing, 400/415/406),
  conditional requests ETag/If-Match/If-None-Match/Last-Modified (per-host config version
  = commit counter from the agent), `Accept`/`Content-Type` `application/yang-data+json`
  (+ `application/yang-data+cbor` as an Arcana extension so the PWA can speak CBOR
  directly and the console passes bodies through untouched — the C→wasm decoder already
  exists), query parameters `content`, `depth`, `fields`, `filter` (streams), `insert`,
  `point`, `start-time`, `stop-time`, `with-defaults` (report-all, trim, explicit,
  report-all-tagged), `ietf-restconf-monitoring:restconf-state/capabilities` listing them.
- `/operations`: `POST /operations/mod:rpc` with `input` wrapper; actions via
  `POST /data/.../action`.
- `PATCH` with `application/yang-patch+json` (RFC 8072) → forwarded as one `EDIT`.
- Errors: `ietf-restconf:errors {error* {error-type, error-tag, error-app-tag, error-path
  (instance-identifier string), error-message, error-info}}` built from the agent's
  `ietf-coreconf:error` (error-tag identity → name → HTTP status via the 8040 §7 table;
  errno kept in `error-info`).
- Streams: `GET /data/ietf-restconf-monitoring:restconf-state/streams` lists streams with
  `access[encoding=json]/location`; `GET <location>` returns `text/event-stream`; each
  event `data: {"ietf-restconf:notification": {"eventTime": "...", "mod:notif": {...}}}`.
  YANG-Push: the browser calls `POST /operations/ietf-subscribed-notifications:
  establish-subscription` (RFC 8650 RESTCONF-notif binding: the response carries the
  subscription id and a `uri` to GET as SSE); the console opens one cblink push stream per
  browser subscription (or shares one agent subscription among identical browser
  subscriptions) and relays frames as SSE after CBOR→JSON translation. SSE reconnects use
  `Last-Event-ID` → `replay-start-time` if the agent supports replay (job traces: yes;
  stats: no).
- NACM: the console maps its WebAuthn users to NACM user names and passes the identity to
  the agent (in `hello` or per-request `cblink:user` structure? Better: per-connection — the
  console opens one agent connection per console user or sends the user in a per-request
  framework structure that only a trusted (certificate-pinned) console may set); the agent
  enforces NACM; the console enforces nothing (single source of truth).
- Fleet: `arcana-fleet:hosts/host[name]/root` with `yangmnt:mount-point root` (`inline`,
  since hosts run different agent revisions): `GET /restconf/data/arcana-fleet:hosts/host=web1/root/ietf-interfaces:interfaces/interface=em0`
  → strip the prefix, translate the remainder to a cblink `GET` with SID instance-identifier
  using host web1's SID tables (cached from its yang-library/sid-file exchange), forward,
  translate the reply. Each host's `yang-library` appears under its `root`; the console's
  own `yang-library` lists `arcana-fleet`, `ietf-yang-schema-mount`, `ietf-yang-library`,
  `ietf-restconf-monitoring`, `ietf-subscribed-notifications`, `ietf-yang-push`,
  `arcana-console` (users, enrolment — the console's own datastore, today in libucl files).
  YANG-Push subscriptions whose filter selects several hosts fan out to several agents and
  are merged (per-host `push-update` events with the host path prefix; dampening at the
  console).
- JSON ↔ CBOR translation (7951 ↔ 9254) is schema-driven: names ↔ SIDs with module
  qualification at module changes, int64/uint64/decimal64 as strings ↔ ints/tag 4, binary
  base64 ↔ bytes, `empty` `[null]` ↔ null, bits names ↔ byte string, enum names ↔ values,
  identityref `mod:name` ↔ SID, instance-identifier string ↔ SID array (parse the XPath-like
  string: `/mod:list[mod:key='v']/leaf`), union discrimination (JSON: by canonical form
  per 7951 §6.12 ↔ CBOR tags 43–46), anydata recursion, metadata annotations (`@`
  objects, RFC 7952: `ietf-origin:origin`) ↔ CBOR annotations? (9254 has no metadata
  encoding; CORECONF carries origin? no — define `cblink:origin` as a sibling map entry
  under a reserved negative delta? Simplest: `with-origin` returns origin as a separate
  parallel structure `cblink:origins {node instance-id, origin}*`; the console folds it into
  `@` annotations).

**D-5:** the console is a full RESTCONF server for the fleet (not a bespoke JSON API), with
`application/yang-data+cbor` pass-through as an extension, SSE for streams, YANG-Push via
RFC 8650-style RESTCONF binding, and the fleet as an `inline` schema mount.

---------------------------------------------------------------------------------------

## (f) Versioning: SIDs versus "numbers are forever" and family versions

- cblink rule: family ids, command ids, attribute ids are never reused; a family has a
  `version` integer; peers compare in `getfamily`.
- RFC 9595 rule: SIDs are never reused or removed; items that disappear get `status
  obsolete` in the `.sid` file; `dependency-revision` records the imported revisions used
  when assigning; the `.sid` file is the ledger committed with the module; new items get
  new SIDs in the module's `assignment-range`s (more ranges can be appended). RFC 7950 §11
  module update rules forbid incompatible changes (no type narrowing, no new mandatory
  nodes, no renames — a rename is deprecate + new node, which is also what gets a new SID).
  Together they are the same discipline as cblink's, with the ledger made explicit.
- Family `version` ↔ module `revision` (date). Capability negotiation ↔ `ietf-yang-library`
  (`content-id` = hash of module set + features + deviations): the console caches per host
  and refreshes on `yang-library-update` notification. A client with a different SID table
  for the same module revision cannot exist if `.sid` files are committed with the module
  and the agent can serve them (`GET-SID`). Features let one binary advertise optional
  parts (`if-mib`, `pre-provisioning`, `multiple-ribs`, `vnet`, `candidate`, `on-change`,
  `configured`); deviations document FreeBSD divergences (global `forwarding`, per-AF MTU)
  instead of silently misbehaving — both are visible in the library.
- SID space: IETF modules with IANA SIDs (coreconf 1000, yang-types 1100, inet-types 1150,
  iana-crypt-hash 1200, netconf-acm 1250, sid-file 1300, interfaces 1500, ip 1600, system
  1700, iana-if-type 1800) use those numbers. Modules without IANA SIDs (routing, v4ur,
  v6ur, network-instance, logical-network-element, yang-library, datastores, origin,
  schema-mount, subscribed-notifications, yang-push, yang-patch, restconf, restconf-
  monitoring, yang-structure-ext) must be assigned by Arcana in a block it owns; use a
  mega-range (RFC 9595 §7: ranges ≥ 1,000,000 in units of 1,000,000, "First Come First
  Served"? — the registry policy: 1000–59999 and 100000–299999 RFC Required; 60000–99999
  experimental (not for deployment); 300000–999999 reserved; mega-ranges by Expert Review —
  Arcana should actually request one from IANA; until then a self-chosen high block, e.g.
  starting at 2^40, with the explicit risk that if IANA later assigns SIDs to those IETF
  modules, Arcana keeps its numbers (no CORECONF interop goal) or runs a one-time re-key of
  both sides, which cblink's "numbers are forever" would forbid — accept and record this).
  Arcana's own modules (`arcana-*`, `cblink`) get sub-ranges of the same block.
- Transition: wire version 2 frames carry YANG; version 1 frames carry legacy families; a
  server accepts both during the migration (cbl_frame already validates `version`); the
  control family is re-expressed as YANG under version 2 (`cblink-ctrl` module) with the
  same semantics.

**D-6:** `.sid` files are the numbers-are-forever ledger; module revision = family version;
yang-library content-id = capability hash; request an IANA mega-range; wire version 2.

---------------------------------------------------------------------------------------

## (g) Expressiveness gap, both directions

cblink has, YANG/YANG-CBOR/CORECONF lack:
1. Credit-based bidirectional streams with half-close, push streams, per-stream reset codes
   (YANG has no transport notion; RESTCONF/NETCONF rely on TCP/HTTP; keep as transport).
2. Multicast groups with "auth required" and best-effort drop + `ENOBUFS` marker (8639
   replaces with subscriptions/suspension; keep NOTIFY as fast path).
3. `dump` as a framed sequence (CORECONF FETCH returns a CBOR sequence; same idea).
4. `flag` = `true` presence (YANG `empty` = null) — wire change, no loss.
5. `float` (YANG has only decimal64) — drop or model as decimal64 with fraction-digits.
6. `any` with no schema (YANG `anydata`/`anyxml` — same).
7. Forward-compatible "ignore unknown attributes" — YANG protocols reject unknown nodes in
   writes; for reads keep lenient.
8. Recursive nested attribute sets (e.g. a step that contains steps): YANG groupings cannot
   recurse; model with a flat list + parent-id leafref, or bounded depth.
9. Dynamic family registration (`newfamily`/`delfamily`): yang-library may change at run
   time (`yang-library-update`), schema mount covers dynamic schemas — equivalent.
10. `COOKIE` in acks and errors, `MSG` warnings in acks: keep as `cblink` structure leaves.
11. Per-op `auth` flag: NACM `default-deny-all` extension on the rpc.
12. Connection-level limits negotiation (`hello` limits): no YANG equivalent; keep as
    `cblink:hello` structure.
13. SCTP multi-streaming, PROXY protocol, AF_UNIX peer credentials: transport, unaffected.

YANG has, cblink lacks (what Arcana gains):
1. A real schema language: typedefs, groupings, augment (third parties can extend Arcana's
   model), deviations, features, identities, union, bits, decimal64, binary, instance-
   identifier, leafref, patterns and lengths, enumerations with names, units, descriptions,
   status lifecycle, defaults.
2. Hierarchical data with keys and ordered lists; choice/case; presence containers;
   anydata; config/state split; NMDA datastores and origin; `with-defaults`.
3. Constraints: mandatory, min/max-elements, unique, must, when, require-instance.
4. Operations semantics: edit-config/YANG Patch operations (merge/replace/create/delete/
   remove/insert/move), candidate/commit/confirmed-commit, rollback-on-error.
5. Actions on list entries and data-node notifications; subscriptions with filters,
   replay, periodic and on-change pushes (YANG Patch deltas), suspension negotiation.
6. Access control (NACM), capability discovery (yang-library), schema mount (jails, FIBs,
   fleet), standard models (interfaces, ip, routing, NI, LNE, system, hardware, ACL, ...)
   and interoperability with RESTCONF/NETCONF/CORECONF tooling (yanglint, pyang,
   OpenDaylight, gNMI bridges).
7. Standard error vocabulary (error-tag/app-tag/path) mapping to HTTP statuses.
Things in YANG that cblink v2 will deliberately not implement (profile): `anyxml` content
validation, full XPath 1.0, XSD regex beyond the subset, `startup` datastore, NETCONF
`lock` across sessions (connection-scoped only), `action`/`rpc` without SID, YANG 1.0
`choice` without `case`? (handled — shorthand is the same in 1.1), `deviate replace` of
`type` (allowed), `ordered-by user` for leaf-lists (support), decimal64 (support via tag 4
but Arcana modules avoid it).

---------------------------------------------------------------------------------------

## (h) Effort estimates (lines of C unless noted; weeks for one engineer; confidence)

| # | Component | New/changed lines | Weeks | Confidence | Notes |
|---|---|---|---|---|---|
| 1 | YANG lexer/parser (7950 §14), submodules, extensions | 1.5k | 1.5 | high | well-specified ABNF |
| 2 | Schema compiler: imports/prefixes, typedef restriction inheritance, groupings/uses/refine/uses-augment, augment (all targets, when), choice/case, deviations, features/if-feature, identities, config/mandatory/status rules, schema-node-id resolution, diagnostics | 5–6k | 7–9 | medium | the corner cases are where libyang spent years; bounded by the module corpus and CI cross-check with pyang/yanglint |
| 3 | XPath-lite parser (shared by generator and runtime) | 1.2k | 1.5 | high | |
| 4 | SID tooling: `.sid` read/write (libucl JSON), verification, assignment per RFC 9595 §6, ranges, obsolete handling, `ietf-sid-file` structure emission | 1.2k | 1.5 | high | |
| 5 | XSD regex → ERE translator + generation-time pattern tests | 0.5k | 1 | medium | fallback: own matcher 0.9k, +1 week |
| 6 | C emitter: structs, schema/SID/identity/feature tables, builders, parsers, handler stubs, markdown + tree diagrams | 5–6k | 5–6 | medium | replaces gen_c.c/gen_md.c |
| 7 | libcblink wire v2: SID-keyed bodies, delta tables, tags 4/43–47, kinds empty/bits/identityref/instance-identifier/union/decimal64, framework-as-structures (`cblink` module: hello, error via ietf-coreconf + augment, credit, close, notification), version-1 coexistence | 3k changed/added (cbl_decode, cbl_attr, cbl_policy, cbl_msg, cbl_frame, cbl_ctrl*, cbl_stream credit frames) | 4 | medium-high | the ctrl family is regenerated from `cblink-ctrl.yang` |
| 8 | Instance data tree + static validator + defaults + keys/unique + identity derivation + leafref resolution + edit-merge engine (merge/replace/create/delete/remove/insert/move) + diff (for on-change) | 5k | 6 | medium | the core of the agent |
| 9 | XPath-lite evaluator (node-sets, coercions, functions incl. derived-from*, deref, re-match) + must/when/filters/parent-reference/NACM path matcher | 3–3.5k | 4 | medium-low | semantics subtleties; fuzz against libyang's results in CI |
| 10 | Datastore engine in arcana-agent: running (rc.conf/rc.conf.d/jail.conf/loader.conf/sysctl.conf/rtadvd.conf round-trip editors preserving comments), candidate + commit + confirmed-commit + rollback, `arcana:live`, operational collectors framework, transaction apply with undo | 6–8k | 8–10 | medium | Arcana already has rc.conf and jail.conf editing (reuse), libjailconf |
| 11 | ietf-interfaces + arcana-interfaces (getifaddrs/if_data/ioctl/netlink, vlan/bridge/lagg/epair, rtsock events) | 2.5k | 3 | high | |
| 12 | ietf-ip (addresses v4/v6, ARP/ND via sysctl/netlink, nd6 flags, lifetimes, autoconf sysctls, static neighbors) | 2k | 2.5 | high | |
| 13 | ietf-routing + v4ur/v6ur (NET_RT_DUMP per FIB / netlink, static routes ↔ rc.conf, ECMP via netlink, active-route via RTM_GET, source-protocol mapping) | 2.5k | 3 | medium-high | |
| 14 | RA submodule ↔ rtadvd.conf + rtadvctl | 0.8k | 1 | medium | termcap-style parser/writer |
| 15 | ietf-network-instance (FIBs: SIOCGIFFIB/SIOCSIFFIB, fib names store, per-FIB RIB mount, parent-reference) | 0.8k | 1 | high | |
| 16 | ietf-logical-network-element (VNET jails: jail_attach helper process over socketpair running the collectors/editors inside the jail, vnet interface moves, bind-lne-name, per-LNE yang-library) | 1.5k | 2.5 | medium | |
| 17 | Port of the existing Arcana family to YANG modules (jails incl. all jail(8) params, services, packages, jobs with actions/notifications, stats, storage/fstab, kernel/sysctl, transport, agent/console update rpcs) — mostly mechanical from arcana.yaml's 430 items | 4k + ~2.5k YANG | 4 | medium-high | |
| 18 | Subscriptions: ietf-subscribed-notifications + YANG-Push on push streams (periodic timers, on-change diff + dampening + YANG Patch emission, subtree filter, XPath filter via #9, state-change notifications, suspension on credit, monitoring counters, configured subscriptions/call-home) | 3.5–4k | 5 | medium | on-change for routes must use rtsock/netlink events, not table diffing |
| 19 | NACM (groups from cert subject/uid, rule-lists, 3 enforcement points, counters, default-deny extensions) | 1.5k | 2 | high | algorithm is exact in 8341 §3.4 |
| 20 | yang-library + schema-mount runtime (per-mount library, nested mounts, dispatch, parent-reference injection) | 1.5k | 2 | medium | |
| 21 | Console: RESTCONF layer in Kore (host-meta, api-path, methods, status table, ETag, query params, errors, YANG Patch, restconf-monitoring, SSE) | 3k | 4 | medium-high | |
| 22 | Console: JSON ↔ CBOR translator (7951 ↔ 9254, schema-driven, instance-identifier strings, annotations/origin) | 2.5k | 3 | high | |
| 23 | Console: fleet schema mount + per-host SID/library cache + proxy + YANG-Push fan-out/relay + NACM identity passing | 1.5k | 2.5 | medium | |
| 24 | PWA: switch to RESTCONF JSON (or CBOR pass-through), SSE subscriptions, schema-driven forms from yang-library | JS/wasm, not C | 3–4 | medium | outside the C count |
| 25 | Tests: generator corpus (IETF modules + pathological), decoder fuzzers with tags, validator unit tests from 7950 examples, XPath tests, datastore round-trip tests on rc.conf fixtures, RESTCONF conformance (a Python RESTCONF client in CI, optional), interop smoke test with a CORECONF client | 5k | 5 | medium | |

Totals: ≈ 58–68k lines of C (new or rewritten; cblink today is 20.7k, of which ~8k survives
untouched: transports, TLS, loop, sock, sctp, proxy, frame, stream mechanics), 2.5–3k lines
of YANG, 80–90 engineer-weeks ≈ 20 months for one engineer, ≈ 11–12 months for two with
the natural split (one on generator+libcblink+validator, one on agent datastores+modules,
console last). Confidence on the total: medium; the two items most likely to overrun are
#2 (schema compiler corners) and #10 (round-tripping FreeBSD config files faithfully).

Phasing (each phase ends with something shippable next to the legacy family):
- Phase 0 (3 w): spike — wire v2 body decoder with SID deltas and tags; hand-written SID
  tables for ietf-interfaces; measure sizes; decide own-parser vs libyang-at-build-time
  (D-3) on the evidence of a 2-week parser prototype.
- Phase 1 (14 w): #1–#7, #11, #12 — generator produces ietf-interfaces/ietf-ip agent code;
  `GET`/`dump` of operational interfaces over cblink v2 next to the legacy `network` op;
  `ctrl` regenerated from YANG.
- Phase 2 (16 w): #8, #9, #10, #13–#16, #20 — datastores, edits with validation, routing,
  FIBs/NIs, VNET jails as LNEs; console reads via a thin translator (#22) for the new tree.
- Phase 3 (14 w): #17, #21, #23, #24 — all Arcana operations as YANG; RESTCONF console;
  legacy family frozen.
- Phase 4 (12 w): #18, #19, #25 — YANG-Push replaces polling, NACM, configured
  subscriptions (agent call-home), legacy family removed.

Risks and mitigations:
- Own YANG compiler correctness → CI cross-check of tree diagrams and resolved types against
  pyang/yanglint on every module; the profile rejects what the compiler does not implement.
- XPath semantics → generation-time subset check; property tests against libyang.
- rc.conf fidelity → keep Arcana-managed values in `/etc/rc.conf.d/arcana-*` fragments where
  rc(8) allows it (rc.conf.d is read per service; for `ifconfig_*` and `static_routes`
  `rc.conf.d/network`? `netif` reads `/etc/rc.conf.d/netif` and `/etc/rc.conf.d/routing`),
  limiting edits to files Arcana owns; a `must`-style check that the user's rc.conf does not
  also define the same variable (conflict → `operation-failed` with a clear message).
- On-change cost on big tables → event-driven (rtsock/netlink) for routes, neighbors,
  interfaces; periodic-only for counters (`on-change-unsupported` for statistics).
- Jail helper processes → one long-lived helper per running VNET jail (attached), lazily
  started, speaking the same cblink v2 over a socketpair (the agent is a cblink client of
  its own helpers; the LNE `root` mount is literally a proxied connection — the same
  mechanism as the fleet mount at the console, which keeps the design uniform).
- SID governance → request an IANA mega-range early; keep `.sid` files under review like
  ABI files.

**D-7:** proceed in the phases above; the decision gate at the end of Phase 0 is D-3
(own compiler vs libyang-at-build-time); everything else in this document is independent
of that gate.
