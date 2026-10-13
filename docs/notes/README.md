# Notes behind PLAN-SDN-YANG.md

One file per RFC read for [../PLAN-SDN-YANG.md](../PLAN-SDN-YANG.md),
written 2026-10-13: the module's complete tree diagrams, every node
with its meaning and a FreeBSD realisation, what cannot be mapped and
why, the features Arcana could advertise, the YANG constructs the
contract must express, and the open decisions. Also the design
analysis of cblink as a YANG protocol and a survey of what FreeBSD
base and ports offer. They are notes, not decisions: the plan says
what was decided. Where a note cites an Internet-Draft, that is for
context; the plan relies on RFCs only.

| File | Subject |
|---|---|
| [cblink-yang-design.md](cblink-yang-design.md) | cblink as a strict YANG protocol — engineering analysis |
| [cblink-v2-frame-sizes.md](cblink-v2-frame-sizes.md) | Frame sizes of an interfaces read, wire version 1 against version 2 (step 0.1.4), with its script |
| [draft-ietf-core-comi.md](draft-ietf-core-comi.md) | draft-ietf-core-comi-21 — CoAP Management Interface (CORECONF) |
| [freebsd-landscape.md](freebsd-landscape.md) | FreeBSD networking landscape for Arcana (SDN + IETF YANG agent contract) |
| [rfc10053.md](rfc10053.md) | RFC 10053 — A Framework for Computing-Aware Traffic Steering (CATS) |
| [rfc7018.md](rfc7018.md) | RFC 7018 — Auto-Discovery VPN Problem Statement and Requirements |
| [rfc7426.md](rfc7426.md) | RFC 7426 — Software-Defined Networking (SDN): Layers and Architecture Terminology |
| [rfc7950.md](rfc7950.md) | RFC 7950 — The YANG 1.1 Data Modeling Language |
| [rfc7951.md](rfc7951.md) | RFC 7951 — JSON Encoding of Data Modeled with YANG |
| [rfc8040.md](rfc8040.md) | RFC 8040 — RESTCONF Protocol |
| [rfc8309.md](rfc8309.md) | RFC 8309 — Service Models Explained (Informational, Jan 2018) |
| [rfc8341.md](rfc8341.md) | RFC 8341 — Network Configuration Access Control Model (NACM) |
| [rfc8342.md](rfc8342.md) | RFC 8342 — Network Management Datastore Architecture (NMDA) |
| [rfc8343.md](rfc8343.md) | RFC 8343 — A YANG Data Model for Interface Management (ietf-interfaces, NMDA) |
| [rfc8344.md](rfc8344.md) | RFC 8344 — A YANG Data Model for IP Management (ietf-ip, NMDA) |
| [rfc8349.md](rfc8349.md) | RFC 8349 — A YANG Data Model for Routing Management (NMDA Version) |
| [rfc8455.md](rfc8455.md) | RFC 8455 — Terminology for Benchmarking SDN Controller Performance |
| [rfc8456.md](rfc8456.md) | RFC 8456 — Benchmarking Methodology for SDN Controller Performance |
| [rfc8519.md](rfc8519.md) | RFC 8519 — YANG Data Model for Network Access Control Lists (ACLs) |
| [rfc8525.md](rfc8525.md) | RFC 8525 — YANG Library |
| [rfc8528.md](rfc8528.md) | RFC 8528 — YANG Schema Mount |
| [rfc8529.md](rfc8529.md) | RFC 8529 — YANG Data Model for Network Instances (ietf-network-instance) |
| [rfc8530.md](rfc8530.md) | RFC 8530 — YANG Model for Logical Network Elements (ietf-logical-network-element) |
| [rfc8568.md](rfc8568.md) | RFC 8568 — Network Virtualization Research Challenges |
| [rfc8578.md](rfc8578.md) | RFC 8578 — Deterministic Networking Use Cases |
| [rfc8639.md](rfc8639.md) | RFC 8639 — Subscription to YANG Notifications |
| [rfc8641.md](rfc8641.md) | RFC 8641 — Subscription to YANG Notifications for Datastore Updates (YANG-Push) |
| [rfc8655.md](rfc8655.md) | RFC 8655 — Deterministic Networking Architecture |
| [rfc8763.md](rfc8763.md) | RFC 8763 — Deployment Considerations for Information-Centric Networking (ICN) |
| [rfc8791.md](rfc8791.md) | RFC 8791 — YANG Data Structure Extensions (sx:structure) |
| [rfc8955.md](rfc8955.md) | RFC 8955 — Dissemination of Flow Specification Rules (BGP FlowSpec), with RFC 8956 (IPv6) |
| [rfc8969.md](rfc8969.md) | RFC 8969 — A Framework for Automating Service and Network Management with YANG (Informational, Jan 2021) |
| [rfc8972.md](rfc8972.md) | RFC 8972 — STAMP Optional Extensions (with RFC 8762, STAMP base, folded in) |
| [rfc8994.md](rfc8994.md) | RFC 8994 — An Autonomic Control Plane (ACP) |
| [rfc9061.md](rfc9061.md) | RFC 9061 — A YANG Data Model for IPsec Flow Protection Based on SDN |
| [rfc9181.md](rfc9181.md) | RFC 9181 — A Common YANG Data Model for Layer 2 and Layer 3 VPNs (Standards Track, Feb 2022) |
| [rfc9182.md](rfc9182.md) | RFC 9182 — A YANG Network Data Model for Layer 3 VPNs (L3NM) (Standards Track, Feb 2022) |
| [rfc9222.md](rfc9222.md) | RFC 9222 — Guidelines for Autonomic Service Agents |
| [rfc9232.md](rfc9232.md) | RFC 9232 — Network Telemetry Framework |
| [rfc9254.md](rfc9254.md) | RFC 9254 — CBOR Encoding of Data Modeled with YANG ("YANG-CBOR") |
| [rfc9315.md](rfc9315.md) | RFC 9315 — Intent-Based Networking: Concepts and Definitions |
| [rfc9342.md](rfc9342.md) | RFC 9342 — Clustered Alternate-Marking Method (with RFC 9341, Alternate-Marking base) |
| [rfc9348.md](rfc9348.md) | RFC 9348 — A YANG Data Model for IP Traffic Flow Security (IP-TFS) |
| [rfc9375.md](rfc9375.md) | RFC 9375 — A YANG Data Model for Network and VPN Service Performance Monitoring |
| [rfc9408.md](rfc9408.md) | RFC 9408 — A YANG Network Data Model for Service Attachment Points (SAPs) (Standards Track, June 2023) |
| [rfc9543.md](rfc9543.md) | RFC 9543 — A Framework for Network Slices in Networks Built from IETF Technologies |
| [rfc9595.md](rfc9595.md) | RFC 9595 — YANG Schema Item iDentifier (YANG SID) |
| [rfc9731.md](rfc9731.md) | RFC 9731 — A YANG Data Model for Virtual Network (VN) Operations |
| [rfc9732.md](rfc9732.md) | RFC 9732 — A Framework for NRP-Based Enhanced Virtual Private Networks |
| [rfc9899.md](rfc9899.md) | RFC 9899 — Extensions to the YANG Data Model for Access Control Lists (ACLs) |
| [rfc9938.md](rfc9938.md) | RFC 9938 — A Framework for the Deterministic Networking (DetNet) Controller Plane |
