# Legal notice, authorization and responsibility

**Product:** Serket — Active Directory Relationship Intelligence  
**Owner:** AraizCorp LLC  
**Notice version:** 2.0 — August 2026  
**Spanish version:** [LEGAL.es.md](LEGAL.es.md)

## 1. Nature of the tool

Serket is dual-use security software. It analyzes relationships, permissions and paths of control in Active Directory. The same evidence can support defensive audits, detection validation and authorized red-team or purple-team exercises. AraizCorp does not present Serket as exclusively defensive or offensive, or as undetectable.

## 2. Ownership

Copyright © 2026 AraizCorp LLC.

Serket, its name, visual identity, product documentation and brand elements are property of AraizCorp LLC. Source code is distributed under the MIT license included in this repository. That software license does not grant rights to AraizCorp trademarks, trade names or visual identity.

## 3. Authorized use

Serket may be used for:

- security audits performed with written authorization;
- red-team, purple-team and control-validation exercises;
- defense, research, education and controlled laboratories;
- analysis of systems owned by the operator.

It must not be used against systems, domains, accounts or data belonging to others without explicit, current and verifiable permission from the owner. Possession of valid credentials or technical access does not replace authorization.

## 4. Operator responsibility

Before running Serket, the operator must:

- confirm the objective, scope, schedule and rules of engagement;
- use only accounts and domain controllers included in that scope;
- assess the effect of LDAP queries and configure an appropriate cadence;
- comply with applicable laws, contracts, internal policies and privacy obligations;
- stop and report any accidental out-of-scope access;
- manually review findings and validation templates before using them or including them in a report.

The interface does not execute actions against the domain. Displayed templates provide context for authorized validation and do not replace professional judgment.

## 5. Data custody and handling

Results may contain account names, trust relationships, permissions, control paths and other sensitive Active Directory information. The operator must:

- store results as confidential evidence;
- limit access to authorized personnel;
- avoid sending data to unapproved external services;
- apply encryption, retention and deletion required by the engagement;
- delete or anonymize data when it is no longer needed.

Native execution binds only to `127.0.0.1`. The container listens on all interfaces internally to work with Docker, but the distributed configuration publishes the port only on host loopback. These controls reduce exposure and do not replace endpoint security.

## 6. Controlled collection and detection validation

The controlled collection profile is intended to avoid unnecessary requests and produce reproducible evidence. It does not imply or guarantee invisibility or the absence of alerts.

Collection telemetry documents searches, pages, entries, duration, transport and stages. It should be compared with domain-controller, SIEM, EDR/NDR and responsible-team records.

## 7. Technical limitations

Serket does not guarantee complete Active Directory coverage or automatic classification of every vector. Known boundaries are documented in the README and interface. An absent result does not prove that a relationship or risk does not exist.

## 8. No warranty and limitation of liability

The software is provided under the no-warranty terms of the MIT license. To the maximum extent permitted by applicable law, AraizCorp LLC accepts no responsibility for illegal, unauthorized, negligent or out-of-scope use, or for decisions made without professional validation of results.

## 9. Acceptance

Running or using Serket means that the operator declares they have sufficient authorization, understand the sensitivity of the data and accept responsibility for its use within the agreed scope.
