# Suricata: the plan

Asked for on 2026-10-19: rules (create, read, change, delete, enable,
disable), Suricata's configuration, statistics, graphs, packet and rule
profiling, performance analysis, NIC and CPU affinity, tuning,
offloading and load balancing, Lua and PCAP, plugins, and IPS at L2,
on the TCP stream and on HTTP bodies.

Measured against the port, security/suricata 8.0.7 with its default
options: IPFW (divert), NETMAP, Lua (built in since 8.0), JA3/JA4, NSS,
plugin support; **no profiling** (`Profiling enabled: no`, `Profiling
rules enabled: no` in `suricata --build-info`), no Hyperscan. Arcana
installs nothing by itself; FreeBSD 16.0 and later.

## What there is

Instances of the Security page and of SD-WAN's ids criterion: the
console writes each one's suricata.yaml (HOME_NET, interfaces by
pcap(3), or one divert(4) port for IPS behind ipfw), its own rules as
text and, optionally, the Emerging Threats Open ruleset fetched by
suricata-update. The agent checks with `suricata -T`, runs, stops
(Stop/Start keeps the configuration), and reads eve.json alerts into
events and the table.

## The phases

Each phase is its own commits, suite and push; the panel, the book and
the YANG/Schema panel follow in the same commits.

### 1. Rules

- **Own rules as a table**, not a text area: each rule a row (action,
  protocol, addresses, ports, msg, sid, rev, options), added, changed,
  deleted, enabled or disabled (a disabled rule is kept, commented out
  in the instance's rules file). A rule is checked by `suricata -T`
  with the instance's configuration before it is kept; the error is
  Suricata's own, on the rule's row.
- **The ruleset's rules**, read by the agent from suricata.rules: a
  table searched by sid, msg, classtype and source file, sorted and
  filtered (tbl.c), paged. Each can be enabled, disabled, or made a
  drop (IPS); the choice is written as suricata-update's own
  `enable.conf`, `disable.conf`, `drop.conf` and `modify.conf` in
  `/usr/local/etc/suricata`, and the ruleset fetched again (no
  download: `--offline`) so the choice holds across updates. Groups by
  classtype or file at once (`group:` lines).
- **Sources**: suricata-update's `list-sources`, `enable-source`,
  `disable-source` (ET Open by default; others the admin chooses, with
  a secret code where a source needs one).
- **Thresholds and suppression**: threshold.config lines per instance
  (`suppress gen_id 1, sig_id N, track by_src, ip ...`).
- Rules reloaded live (`suricatasc -c reload-rules` over the
  instance's unix socket) instead of a restart; failed rules read with
  `ruleset-failed-rules`.

### 2. Configuration

A form per instance for the parts of suricata.yaml that matter, the
rest Suricata's defaults; an Advanced YAML overlay for anything else,
checked by `suricata -T`:

- runmode (`workers`, `autofp`), `max-pending-packets`, detect profile
  and `sgh-mpm-context`, `mpm-algo` (`hs` only with Hyperscan built);
- eve-log types: alert, anomaly, http, dns, tls, ssh, flow, netflow,
  files, drop, stats, with the alert's payload and metadata;
- memcaps: flow, stream, reassembly, defrag, host, http;
- the unix socket of each instance (for 1, 3, 4).

### 3. Statistics and graphs

- `stats` in eve-log every 10 s, read by the agent with the alerts:
  capture packets and kernel drops, decoder, flows, TCP sessions,
  memcap hits, alerts, app-layer flows per protocol; kept as a ring of
  points per instance (an hour at 10 s, a day at 5 min), in the read.
- The panel: packets/s and drop %, alerts/s, flows by protocol, memory
  against memcaps, as graphs; top signatures, top sources and
  destinations, alerts by category and severity, over a chosen window.
- Live counters from `suricatasc -c dump-counters` and `iface-stat`.

### 4. Profiling and performance analysis

- **Rule profiling** needs Suricata built with
  `--enable-profiling-rules` (cheap) or `--enable-profiling` (packet
  profiling too, costly). The agent reads `--build-info` and says which;
  without, the panel says what is missing and offers a poudriere build
  (Arcana's poudriere tab) with `CONFIGURE_ARGS+=--enable-profiling-rules`
  in that jail's make.conf for security/suricata, installed by the admin.
  With it: `profiling.rules` written as JSON, the top rules by ticks,
  checks and matches; started and stopped live
  (`ruleset-profile-start`/`-stop`).
- **Packet profiling** (with `--enable-profiling`): per-protocol and
  per-stage ticks.
- **Analysis**: from 3.'s counters, what is wrong and what to change:
  kernel drops over 1 % (workers runmode, more threads, netmap instead
  of pcap, a larger bpf(4) buffer, `net.bpf.zerocopy_enable`), memcap
  hits (which memcap), flow emergency mode, reassembly gaps, decoder
  invalid packets (offloading, see 5.).

### 5. NIC, CPU, offloading and load balancing

- **Offloading**: per watched interface, ifconfig(8)'s `rxcsum`,
  `txcsum`, `tso`, `lro`, `vlanhwtag` shown and, with a button, turned
  off (what Suricata needs to see packets as they are on the wire), and
  kept in rc.conf.
- **Load balancing**: netmap(4) with one thread per RX ring (`threads:
  auto`), the NIC's RSS spreading flows; autofp for pcap, with
  `autofp-scheduler: hash`.
- **CPU affinity**: `threading.cpu-affinity` from the host's CPUs
  (hw.ncpu, NUMA domains from vm.ndomains), management and worker
  sets chosen in the form; the agent checks the CPUs exist (cpuset(1)).
  Interrupt binding of the NIC's queues (cpuset -x) shown beside it.
- **Tuning** presets by the host's size: small (2 CPUs), medium, large;
  each a set of 2.'s values, then adjustable.

### 6. IPS modes

- **L3, divert** (there today): ipfw's divert rules hand packets to
  Suricata (divert(4)).
- **L2, netmap**: Suricata between two interfaces in netmap(4) IPS
  mode (`copy-mode: ips`, `copy-iface`), a bump in the wire that needs
  no addresses; or between an interface and the host stack (`em0` and
  `em0^`). A pair can't also be a bridge member; the form checks it.
- **TCP stream**: `stream.inline: auto`, reassembly depth, midstream
  pickup, async one-sided; exception policies (`exception-policy`,
  drop-flow or pass-flow on memcap and midstream).
- **HTTP bodies**: libhtp's `request-body-limit`,
  `response-body-limit`, inspect window and minimal size,
  decompression limits; file extraction off by default.

### 7. Lua and PCAP

- **Lua rules**: scripts uploaded per instance into its own directory,
  `security.lua.allow-rules: yes` set only when one is there; the `lua:`
  keyword in own rules points at them. Lua output scripts likewise.
- **PCAP offline**: a capture file uploaded (or one of the host's)
  run through an instance's configuration and rules as a job
  (`suricata -r file -l dir`), its alerts shown like live ones.
- **pcap-log**: packets kept for alerts only (conditional), in a size
  limited ring, downloadable from the alert's row.

### 8. Plugins

Suricata 8's plugins (`plugins:` in suricata.yaml, shared objects for
capture or eve output): the admin names one installed on the host; the
agent checks it is a file under /usr/local/lib and root's, and Suricata
`-T` checks it loads. Arcana ships none.

## Order

1, 2 and 3 first (the daily use), then 6 (IPS), 5, 4, 7, 8. Each tested
with stand-ins in agent_test and pwa_test, and with the real Suricata
8.0.7 in the lab (a vnet jail pair with epairs for netmap IPS).
