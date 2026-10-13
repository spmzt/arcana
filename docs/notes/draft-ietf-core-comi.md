# draft-ietf-core-comi-21 — CoAP Management Interface (CORECONF)

Source: /tmp/claude-0/-home-user-arcana/c5b51962-0391-52a9-87d4-18bb94158d90/scratchpad/rfc/draft-ietf-core-comi-21.txt (2 March 2026, 2744 lines, read in full).

## Purpose

YANG management over CoAP with YANG-CBOR (RFC 9254) payloads keyed by SIDs (RFC 9595). It is
"not RESTCONF over CoAP": decisions are driven by byte savings. It is the closest existing
design to "YANG over integer-keyed CBOR", hence the template for cblink's operation mapping.

## Architecture (section 2)
- YANG modules → single **unified datastore** (config true + config false together,
  read-write, changes applied immediately or with minimal delay). NMDA is explicitly out of
  scope. Identity `coreconf:unified` (SID 1029) with base `ds:datastore`.
- Event stream resource(s) for notifications (a server may offer several).
- Security: DTLS or OSCORE; NoSec NOT RECOMMENDED.
- Differences from RESTCONF: FETCH/iPATCH instead of GET+fields/PATCH; no HEAD/OPTIONS; no
  `insert`/`point` query parameters; no `start-time`/`stop-time` replay; SIDs instead of
  names; with-defaults supports only `report-all` and `trim`.

## Identifiers (2.2)
- Instance-identifiers per RFC 9254 §6.13.1: a bare SID for single-instance nodes; an array
  `[SID, key1, key2, …]` for nodes inside lists (keys from the top list down). Carried in
  FETCH and iPATCH payloads (not in the URI).

## Media types (2.3)
- `application/yang-identifiers+cbor-seq`: a CBOR **sequence** (RFC 8742) of
  instance-identifiers. FETCH request body.
- `application/yang-instances+cbor-seq`: a CBOR sequence of one-entry CBOR maps
  `{instance-identifier: instance-value}`. The **reference SID for the value's deltas is the
  SID in the instance-identifier**. Used by FETCH response, iPATCH request, event stream GET
  response, RPC/action POST request and response.
- `application/yang-data+cbor; id=sid`: a single CBOR map of SID → value for whole-datastore
  GET/PUT/POST.
- iPATCH semantics of yang-instances: for each D in the payload, if the datastore has an
  instance I with the same instance-identifier, D's value replaces I; `null` value removes I;
  otherwise D is created (unless null). Idempotent.

## Resources and methods (section 3)
| Resource | rt | Example path |
|---|---|---|
| datastore | core.c.ds | /c (link attribute `ds=<SID of datastore identity>`) |
| default event stream | core.c.ev / core.c.es | /s |
| data nodes (optional discovery) | core.c.dn | /c/<base64url SID> |
| YANG library | core.c.yl | /c/<sid> |

| Method | Use |
|---|---|
| FETCH | retrieve specific data nodes of a datastore or event stream (filter) |
| iPATCH | idempotently create/replace/delete data node(s) |
| POST | invoke an RPC or action (on the datastore resource; the payload names the rpc/action) |
| GET | whole datastore or event stream (Observe for subscriptions) |
| PUT | create or replace the whole datastore |
| DELETE | delete the whole datastore |

### Query parameters (3.1)
- `c` (content): `c` config only, `n` non-config only, `a` all (default). GET/FETCH only.
- `d` (with-defaults): `a` report-all, `t` trim (default). A leaf with a default that was
  never set MUST be returned when it is itself the target; for containers/lists, children at
  default are omitted when d=t and returned when d=a.

### FETCH (3.1.3)
- Request: CBOR seq of instance-identifiers. Response: CBOR seq of `{SID: value}` maps **in
  the same order**; `null` for nodes unsupported or not instantiated. List-instance keys
  SHOULD be elided in the response (only the SID, so the response entry format equals a GET
  response); the client remembers which instance it asked for.
- Example: `1723, [1533, "eth0"]` → `{1723: "2014-10-26T12:16:31Z"}, {1533: {4: "eth0", 1:
  "Ethernet adaptor", 5: 1880, 2: true, 11: 3}}` (type is identityref → SID 1880 =
  ethernetCsmacd; oper-status enum value 3 = testing).

### Data editing (3.2)
- Server MUST preserve the relative order of user-ordered list/leaf-list entries received in
  one edit (arrays preserve order).
- POST = rpc/action invocation only (not "create", unlike RESTCONF).
- iPATCH: no query parameters; payload per media type above; 2.04 Changed. Example: set
  `{1755: true}`, delete `{[1756, "tac.nrc.ca"]: null}`, create/replace `{1756: {3:
  "tic.nrc.ca", 4: true, 5: {1: "132.246.11.231"}}}` — note the list entry is sent as a
  map keyed by the *list* SID with the entry's content (not wrapped in an array) and keyed
  by its key leaf value inside.

### Whole datastore (3.3)
GET → `{SID: value, …}` for all top-level nodes of all modules (e.g. `{1721: {…}, 1533:
[{…}]}`); PUT/POST replace/create; DELETE deletes.

### Event stream (3.4)
- GET with Observe(0); each response carries one or more notifications as a CBOR seq of
  `{notification-SID: content-map}`; newest first at index 0; the same notification may be
  re-sent across responses (reliability by repetition); aggregation period is implementation
  choice; empty-content notification = empty sequence.
- Filtering: FETCH + Observe with a yang-identifiers seq of the wanted notification SIDs; a
  server that does not filter may ignore the payload.

### RPC and action (3.5)
- POST to the datastore resource; payload `{rpc-SID: input-map}` or `{[action-SID, keys…]:
  input-map}`; response `{rpc-SID: output-map}` or `{rpc-SID: null}` when there is no
  output. Input/output maps use deltas relative to the rpc/action SID (RFC 9254 §4.2.1).
  Success is 2.04 Changed.

## Block-wise (section 4)
Large payloads via RFC 7959 blocks; race conditions when the datastore changes during
serialisation; indefinite-length CBOR suggested for streaming (not relevant to cblink, which
has its own frame length and streams).

## Discovery (section 5)
YANG library (draft-ietf-core-yang-library, the constrained variant of RFC 8525) at
`rt=core.c.yl`; `/.well-known/core` for datastore (`ds=` SID), data nodes, event streams.

## Error handling (section 6)
- 4.xx/5.xx; a failing request MUST NOT affect the datastore (all-or-nothing).
- CoAP-level: 4.01 unauthorized, 4.02 bad option, 4.04 not found (non-instantiated data
  node/rpc/stream), 4.05 method not allowed (GET on an rpc; PUT/POST on config false), 4.08,
  4.13, 4.15 unsupported content-format.
- YANG-constraint errors: 4.00 Bad Request with `sx:structure error` of module
  `ietf-coreconf` (SID 1024) encoded per RFC 9254 §5:
  ```
  +--rw error!
     +--rw error-tag             identityref   (mandatory; base error-tag)
     +--rw error-app-tag?        identityref   (base error-app-tag)
     +--rw error-data-node?      instance-identifier
     +--rw error-message?        string
  ```
  error-tag identities: operation-failed, invalid-value, missing-element, unknown-element,
  bad-element, data-missing, error.
  error-app-tag identities: malformed-message, data-not-unique, too-many-elements,
  too-few-elements, must-violation, duplicate (under operation-failed); invalid-datatype,
  not-in-range, invalid-length, pattern-test-failed (under invalid-value); missing-key,
  missing-input-parameter (under missing-element); instance-required, missing-choice (under
  data-missing).
  Example: `{1024: {4: 1011, 1: 1018, 2: 1740, 3: "maximum value exceeded"}}`.
- Module `ietf-coreconf@2026-03-02` and its `.sid` file (range 1000/100) are normative
  appendices: module 1000; identities 1001..1023 and 1029 (unified); data
  `/ietf-coreconf:error` 1024, `/error-app-tag` 1025, `/error-data-node` 1026,
  `/error-message` 1027, `/error-tag` 1028. Note the identities were assigned in sorted
  order and `unified` (1029) was appended later — a live example of "append, never reorder".

## What cblink can take from CORECONF

1. **Operation shape.** Four primitives suffice: FETCH (read by instance-identifier list),
   iPATCH (idempotent merge/replace/delete by instance-identifier with `null` = delete),
   POST (rpc/action by SID / [SID, keys]), event stream (notification SID + content).
   cblink `do` ≈ FETCH/iPATCH/POST; `dump` ≈ FETCH of a list / whole datastore GET
   streamed one entry per MULTI frame; `notify` ≈ event stream; `stream` ≈ Observe.
2. **Payload envelopes.** `{instance-identifier: value}` with the reference SID taken from
   the identifier is the exact analogue of cblink's "header names the command, body is the
   attribute map": put the target SID (or `[SID, keys]`) in the body's single map entry, or
   put the SID in the header and send the bare value. Both are RFC 9254-conformant.
3. **Error model.** `ietf-coreconf:error` (error-tag identityref, error-app-tag, error-data-node
   instance-identifier, error-message) maps one-to-one onto cblink's framework attributes
   CODE/MSG/PATH/MISS_TYPE — PATH becomes an instance-identifier (`[SID, keys…]`), CODE
   becomes an identityref SID (plus errno for transport-level errors).
4. **Unified datastore** is the pragmatic choice for an agent that applies changes
   immediately (as arcana-agent does today through jail(8)/sysrc/ifconfig). NMDA's
   running/intended/operational split can be added later as separate datastore identities
   if needed (RFC 8342 notes).
5. **Limits of CORECONF** to be aware of: no `insert`/`point` for ordered-by user lists, no
   replay, no NMDA, no NACM integration spelled out, FETCH responses elide keys (fine for
   request/response correlation on cblink's seq), no transactional multi-datastore edit
   (iPATCH is atomic per request, which is enough).
