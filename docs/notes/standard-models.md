# Standard YANG models for what Y-3 converts

Checked 2026-10-14, before converting the rest of arcana.yaml (the
user: "double check RFCs or existing yang models ... to NOT accidentally
reinvent the wheel"). For each area, what the IETF (or MEF) already has,
and what Arcana does with it. A published RFC is used as it is, with
Arcana's own augments and deviations for what FreeBSD has or lacks; a
working-group draft is followed where it is stable, its module kept at
the revision taken until it is an RFC; an Arcana module is written only
where nothing exists.

| Area | Standard | Status | Arcana |
|---|---|---|---|
| Host facts: hostname, platform (os-name, os-release, machine), clock, boot time, users, DNS resolver, restart, shutdown | `ietf-system`, RFC 7317 | RFC | 3.1.9 uses it; `arcana-host` only augments it (role, router-id, capabilities, plugins) |
| Hardware inventory: CPUs, memory, disks (class storage-drive), sensors (temperatures) | `ietf-hardware`, RFC 8348 | RFC | 3.1.9 fills it; the disks of `arcana-storage` (3.1.5) are also its components, serial and model as RFC 8348 has them |
| Software inventory (packages, the OS) | `draft-ietf-ivy-network-inventory-software` | WG draft | `arcana-packages` (3.1.3) stays; aligned with the draft's names when it is an RFC |
| Logging configuration (syslog.conf actions) | `ietf-syslog`, RFC 9742 | RFC | syslog.conf as `ietf-syslog` (3.1.7); the log operation's reading of the logs is `arcana-log`, which RFC 9742 does not cover |
| Faults, alarms | `ietf-alarms`, RFC 8632 (in share/yang) | RFC | the SD-WAN faults (Mplify 119) and the events that are faults as alarms (3.1.7, 3.1.12) |
| Events, history, processes | none | - | `arcana-events`, `arcana-history`, `arcana-processes` |
| Schedules (workflows' times) | `draft-ietf-netmod-schedule-yang` | WG draft | the workflows' schedules, when converted, by its groupings |
| NTP | `ietf-ntp`, RFC 9249 | RFC | the ntp job kind's configuration and ntpd's state |
| Keys, certificates, trust anchors | `ietf-crypto-types` RFC 9640, `ietf-truststore` RFC 9641, `ietf-keystore` RFC 9642 | RFC | certs (the CA, trust) through them |
| SSH, TLS, TCP servers and clients | `ietf-ssh-server` RFC 9644, `ietf-tls-server` RFC 9645, `ietf-tcp-server` RFC 9643 | RFC | ssh (sshd), tls, transport (cblink's listeners) through their groupings |
| IPsec, IKEv2 | `ietf-i2nsf-ike`, `-ikeless`, RFC 9061 (in share/yang) | RFC | the ipsec job kinds' state |
| ACLs, firewall rules | `ietf-access-control-list`, RFC 8519 (in share/yang) | RFC | ipfw-rules and fw-trace through it, ipfw the engine (D-7, the user's) |
| QoS (dummynet) | `draft-ietf-rtgwg-qos-model` | WG draft | 3.1.10 follows it; dummynet's pipes and queues an augment |
| OSPF, RIP, Babel, BFD | RFC 9129, RFC 8695, RFC 9647, RFC 9314 | RFC | bird-config's protocols (3.1.8) as these, BIRD the engine |
| BGP | `draft-ietf-idr-bgp-model` (-21, August 2026) | WG draft | 3.1.8 follows it |
| Ping, traceroute | `ietf-connectionless-oam`, `-methods`, RFC 8532, RFC 8533 | RFC | traceroute (3.1.11) as RFC 8533's traceroute rpc |
| Active measurement (probes) | STAMP: `draft-ietf-ippm-stamp-yang`; TWAMP: RFC 8913 | WG draft; RFC | the probes (3.1.11) as STAMP's, D-8 having chosen STAMP |
| Network topology | `ietf-network`, `-topology`, RFC 8345 (in share/yang) | RFC | the mesh and the topology view |
| SD-WAN | MEF 70.2 publishes no YANG; `draft-sun-opsawg-sdwan-service-model` (individual, expired) | none usable | `arcana-sdwan` (3.1.12) by MEF 70.2's attributes; L3NM where they overlap (D-4) |
| WireGuard, netgraph, packet capture, plugins | none | - | Arcana's own |
| Jails, services, sysctl, the kernel | none (a vnet jail's network is RFC 8530's LNE) | - | Arcana's own (3.1.1, 3.1.2, 3.1.6) |

Sources: [RFC 7317](https://www.rfc-editor.org/rfc/rfc7317), [RFC 8348](https://www.rfc-editor.org/rfc/rfc8348.html),
[draft-ietf-ivy-network-inventory-software](https://datatracker.ietf.org/doc/html/draft-wzwb-ivy-network-inventory-software-02),
[RFC 9742](https://www.rfc-editor.org/rfc/rfc9742.html), [RFC 8632](https://www.rfc-editor.org/rfc/rfc8632),
[draft-ietf-netmod-schedule-yang](https://www.ietf.org/archive/id/draft-ietf-netmod-schedule-yang-10.html),
[RFC 9249](https://www.rfc-editor.org/rfc/rfc9249.html), [RFC 9640](https://www.rfc-editor.org/rfc/rfc9640.html),
[RFC 9641](https://www.rfc-editor.org/rfc/rfc9641.html), [RFC 9642](https://www.rfc-editor.org/rfc/rfc9642.html),
[RFC 9643](https://www.rfc-editor.org/rfc/rfc9643), [RFC 9644](https://www.rfc-editor.org/rfc/rfc9644.html),
[RFC 9645](https://www.rfc-editor.org/rfc/rfc9645.html), [RFC 9061](https://www.rfc-editor.org/rfc/rfc9061.html),
[RFC 8519](https://www.rfc-editor.org/rfc/rfc8519), [draft-ietf-rtgwg-qos-model](https://datatracker.ietf.org/doc/draft-ietf-rtgwg-qos-model/),
[RFC 9129](https://www.rfc-editor.org/rfc/rfc9129.html), [RFC 8695](https://www.rfc-editor.org/rfc/rfc8695.html),
[RFC 9647](https://www.rfc-editor.org/rfc/rfc9647.html), [RFC 9314](https://www.rfc-editor.org/rfc/rfc9314.html),
[draft-ietf-idr-bgp-model](https://datatracker.ietf.org/doc/html/draft-ietf-idr-bgp-model),
[RFC 8532](https://www.rfc-editor.org/rfc/rfc8532.html), [RFC 8533](https://datatracker.ietf.org/doc/rfc8533/),
[draft-ietf-ippm-stamp-yang](https://datatracker.ietf.org/doc/html/draft-ietf-ippm-stamp-yang-12),
[draft-sun-opsawg-sdwan-service-model](https://datatracker.ietf.org/doc/html/draft-sun-opsawg-sdwan-service-model).
