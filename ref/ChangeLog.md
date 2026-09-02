# Change Log for keripy

## 1.2 release series

This history was reconstructed on 2026-09-02 from exact PyPI source
distributions, signed and historical tags, maintenance branches in the
WebOfTrust and GLEIF-IT repositories, commit ancestry, and GitHub pull-request
and issue metadata. Versions 1.2.8 through 1.2.11 were versioned maintenance
milestones but were not published to PyPI. Their tags document the historical
lines that were subsequently consolidated in the published 1.2.12 release.

Release tags in this series follow the repository convention `1.2.x` without a
leading `v`.

### 1.2.14 (Unreleased)

Current release-branch baseline: [`eaf104322b85`](https://github.com/WebOfTrust/keripy/commit/eaf104322b85f5576b6106a4a7a45c6ac788c44c). The final `1.2.14` tag will be created from the merged release commit.

#### Highlights

- Adds credential registry rename/import/export workflows, multisig import/export improvements, witness query support, configurable scheduler tocks, QNF idempotence, ESSR/SPAC fixes, and several CLI and ACDC correctness repairs.
- Improves witness configuration and publisher lifecycle handling, admits complete TCP stream payloads, avoids redundant completed-receipt messengers, and makes TCP/HTTP messenger idle accounting track actual queued and in-progress work.
- The experimental HIO dependency, deterministic witness teardown, and Directant close changes from PRs #1635, #1614, and #1638 were reverted by PRs #1647, #1649, and #1648. They are not part of the final 1.2.14 behavior.

#### Merged pull requests

- [WebOfTrust #854](https://github.com/WebOfTrust/keripy/pull/854) — Missing sn in CloneCred after fix in PR #682
- [WebOfTrust #1461](https://github.com/WebOfTrust/keripy/pull/1461) — feat: kli vc registry rename
- [WebOfTrust #1462](https://github.com/WebOfTrust/keripy/pull/1462) — feat: backport kli vc schema import from main
- [WebOfTrust #1463](https://github.com/WebOfTrust/keripy/pull/1463) — feat: --registry-name opt for multisig join
- [WebOfTrust #1464](https://github.com/WebOfTrust/keripy/pull/1464) — feat: --all-registries, --all-credentials for kli vc export
- [WebOfTrust #1465](https://github.com/WebOfTrust/keripy/pull/1465) — feat: backport and expand kli import
- [WebOfTrust #1466](https://github.com/WebOfTrust/keripy/pull/1466) — feat: add multisig export import workflow
- [WebOfTrust #1447](https://github.com/WebOfTrust/keripy/pull/1447) — feat: consume and discard KERIACDCGenusVersion
- [WebOfTrust #1487](https://github.com/WebOfTrust/keripy/pull/1487) — Log kli witness start failures and prevent startup stalls (#238) — v1.2 backport
- [WebOfTrust #1537](https://github.com/WebOfTrust/keripy/pull/1537) — Fix small klass -> klas typo
- [WebOfTrust #1593](https://github.com/WebOfTrust/keripy/pull/1593) — Keep service tocks generator-local
- [WebOfTrust #1592](https://github.com/WebOfTrust/keripy/pull/1592) — Fix scheduler tock boundaries
- [WebOfTrust #1594](https://github.com/WebOfTrust/keripy/pull/1594) — Clean up Signaler tocks (code) and clarify scheduling ownership (docs)
- [WebOfTrust #1597](https://github.com/WebOfTrust/keripy/pull/1597) — fix: leader election for SignifyGroupHabs
- [WebOfTrust #1585](https://github.com/WebOfTrust/keripy/pull/1585) — feat: tocks from configs, envs superseding file
- [WebOfTrust #1603](https://github.com/WebOfTrust/keripy/pull/1603) — Backport to v1.2.14: fix: make sure that ESSR attachments survive an escrowed event
- [WebOfTrust #1602](https://github.com/WebOfTrust/keripy/pull/1602) — Backport to v1.2.14: fix: add null check for issuee in sendArtifacts for presenting untarg…
- [WebOfTrust #1601](https://github.com/WebOfTrust/keripy/pull/1601) — Backport to v1.2.14: fix: full size of 1AAE should be 156, not 56
- [WebOfTrust #1600](https://github.com/WebOfTrust/keripy/pull/1600) — Backport to v1.2.14: fix: SerderACDC should set issuee when specified
- [WebOfTrust #1599](https://github.com/WebOfTrust/keripy/pull/1599) — Backport to v1.2.14: Missing sn in CloneCreds after fix in PR #682
- [WebOfTrust #1604](https://github.com/WebOfTrust/keripy/pull/1604) — Backport to v1.2.14: fix: elide IPEX notifications for local IPEX initiator
- [WebOfTrust #1605](https://github.com/WebOfTrust/keripy/pull/1605) — Backport to v1.2.14: feat: Add query endpoints to witnesses
- [WebOfTrust #1606](https://github.com/WebOfTrust/keripy/pull/1606) — Backport to v1.2.14: fix: set eid on OOBI processReply when available
- [WebOfTrust #1607](https://github.com/WebOfTrust/keripy/pull/1607) — Backport to v1.2.14: feat: Switched internal receipting mechanism of Registrar to use Receiptor
- [WebOfTrust #1579](https://github.com/WebOfTrust/keripy/pull/1579) — fix(eventing): make QNF escrow retries idempotent
- [WebOfTrust #1565](https://github.com/WebOfTrust/keripy/pull/1565) — feat: align SPAC/ESSR usage with keripy main
- [WebOfTrust #1616](https://github.com/WebOfTrust/keripy/pull/1616) — chore(ci): pin action SHAs + move off deprecated Node runtimes
- [WebOfTrust #1635](https://github.com/WebOfTrust/keripy/pull/1635) — Use gleif_hio 0.6.20rc2 on v1.2.14 — reverted by #1647
- [WebOfTrust #1634](https://github.com/WebOfTrust/keripy/pull/1634) — fix: backport incomplete Serder shortage handling
- [WebOfTrust #1633](https://github.com/WebOfTrust/keripy/pull/1633) — fix: avoid stale HTTP messenger state
- [WebOfTrust #1614](https://github.com/WebOfTrust/keripy/pull/1614) — fix: make witness transmission teardown deterministic — reverted by #1649
- [WebOfTrust #1638](https://github.com/WebOfTrust/keripy/pull/1638) — Close direct connections without Reactants immediately — reverted by #1648
- [WebOfTrust #1647](https://github.com/WebOfTrust/keripy/pull/1647) — Revert "Use gleif_hio 0.6.20rc2 on v1.2.14"
- [WebOfTrust #1648](https://github.com/WebOfTrust/keripy/pull/1648) — Revert "Close direct connections without Reactants immediately"
- [WebOfTrust #1649](https://github.com/WebOfTrust/keripy/pull/1649) — Revert "fix: make witness transmission teardown deterministic"
- [WebOfTrust #1650](https://github.com/WebOfTrust/keripy/pull/1650) — fix: read witness AIDs from config mapping
- [WebOfTrust #1651](https://github.com/WebOfTrust/keripy/pull/1651) — fix: resolve WitnessPublisher lifecycle bugs (#1652)
- [WebOfTrust #1653](https://github.com/WebOfTrust/keripy/pull/1653) — Fix #1654: Admit TCP stream payloads
- [WebOfTrust #1655](https://github.com/WebOfTrust/keripy/pull/1655) — Avoid scheduling messengers for completed receipts
- [WebOfTrust #1657](https://github.com/WebOfTrust/keripy/pull/1657) — Fix messenger idle accounting
- [WebOfTrust #1660](https://github.com/WebOfTrust/keripy/pull/1660) — Correct KLI challenge file and mailbox request paths

#### Closed issues

- [WebOfTrust #238](https://github.com/WebOfTrust/keripy/issues/238) — Ensure `kli witness start` logs errors correctly
- [WebOfTrust #892](https://github.com/WebOfTrust/keripy/issues/892) — full size of 1AAE should be 156, not 56

Note: Issues #1652, #1654, and #1656 are associated with included fixes but GitHub still reports them as open, so they are not listed as closed issues.

### 1.2.13 (2026-05-06)

Tag [`1.2.13`](https://github.com/WebOfTrust/keripy/tree/1.2.13) targets [`cbbf700fa809`](https://github.com/WebOfTrust/keripy/commit/cbbf700fa8091587b96b5475c5f50d1d8bf3ca40). PyPI sdist SHA-256: `aef033ec3b17d4b04d8801b5365b225b6cba5630a67aaad2f306aaecbd256fcd`.

#### Highlights

- Prevented a Reger LMDB environment from being opened twice.

#### Merged pull requests

- [WebOfTrust #1366](https://github.com/WebOfTrust/keripy/pull/1366) — fixes #1357 double Reger open LMDB error
- [WebOfTrust #1385](https://github.com/WebOfTrust/keripy/pull/1385) — bump to 1.2.13 for Reger double open bugfix with #1366

#### Closed issues

- No separately closed issue was identified for this release boundary.

Note: PR #1366 describes itself as fixing issue #1357, but GitHub still reports that issue as open.

### 1.2.12 (2026-03-04)

Tag [`1.2.12`](https://github.com/WebOfTrust/keripy/tree/1.2.12) targets [`4ee02c021377`](https://github.com/WebOfTrust/keripy/commit/4ee02c0213770d25a0114fe7ebd7ab4ab5500cde). PyPI sdist SHA-256: `06c86aee587b81f1975b21e61a33b2402edf2ede47c0d7e693f66faad28ecae6`.

#### Highlights

- Published the consolidated 1.2 maintenance line, including the work previously represented by the 1.2.8 through 1.2.11 historical milestones.
- Added the final HIO temporary-resource compatibility update and corrected group-hab naming during multisig joins.

#### Merged pull requests

- [WebOfTrust #1004](https://github.com/WebOfTrust/keripy/pull/1004) — fixes imports
- [WebOfTrust #968](https://github.com/WebOfTrust/keripy/pull/968) — Update Doer method signatures to support new Hio multiprocessing safety
- [WebOfTrust #1083](https://github.com/WebOfTrust/keripy/pull/1083) — fix: correct indentation
- [WebOfTrust #1089](https://github.com/WebOfTrust/keripy/pull/1089) — chore: bump version to 1.2.7
- [WebOfTrust #1093](https://github.com/WebOfTrust/keripy/pull/1093) — env only approach to configuring db sizes.
- [WebOfTrust #1154](https://github.com/WebOfTrust/keripy/pull/1154) — V1.2.7 runner
- [WebOfTrust #1155](https://github.com/WebOfTrust/keripy/pull/1155) — Add kli contacts commands
- [WebOfTrust #1165](https://github.com/WebOfTrust/keripy/pull/1165) — fix: provide issuer prefix for telquery on admit
- [WebOfTrust #1113](https://github.com/WebOfTrust/keripy/pull/1113) — fix: allow tests to use temp=True properly for Configer
- [WebOfTrust #1111](https://github.com/WebOfTrust/keripy/pull/1111) — fix: remove dip and drt from escrows once approved
- [WebOfTrust #1114](https://github.com/WebOfTrust/keripy/pull/1114) — fix: backport multisig delegation fixes from main
- [WebOfTrust #1110](https://github.com/WebOfTrust/keripy/pull/1110) — fix: multisig join should use icp ked not exn ked
- [WebOfTrust #1112](https://github.com/WebOfTrust/keripy/pull/1112) — docs: clean up and add agenting docs
- [WebOfTrust #1227](https://github.com/WebOfTrust/keripy/pull/1227) — config tocks
- [WebOfTrust #1228](https://github.com/WebOfTrust/keripy/pull/1228) — Enc/escrow metrics
- [WebOfTrust #1229](https://github.com/WebOfTrust/keripy/pull/1229) — adds escrow clear
- [WebOfTrust #1230](https://github.com/WebOfTrust/keripy/pull/1230) — feat: get aid allowlists from witness config file
- [WebOfTrust #1231](https://github.com/WebOfTrust/keripy/pull/1231) — Escrow logging error fix gleif 1 2 8
- [WebOfTrust #1232](https://github.com/WebOfTrust/keripy/pull/1232) — fix: match dig or edig type to db function return type
- [WebOfTrust #1233](https://github.com/WebOfTrust/keripy/pull/1233) — Rp missing field compat
- [WebOfTrust #1234](https://github.com/WebOfTrust/keripy/pull/1234) — bump version to 1.2.8
- [WebOfTrust #1235](https://github.com/WebOfTrust/keripy/pull/1235) — fix: delegator seal storage
- [WebOfTrust #1236](https://github.com/WebOfTrust/keripy/pull/1236) — adds a clean and inspect command
- [WebOfTrust #1237](https://github.com/WebOfTrust/keripy/pull/1237) — export escrow metrics
- [WebOfTrust #1238](https://github.com/WebOfTrust/keripy/pull/1238) — support new temp arg for HIO doified functions
- [WebOfTrust #1239](https://github.com/WebOfTrust/keripy/pull/1239) — bump version to 1.2.12
- [WebOfTrust #1267](https://github.com/WebOfTrust/keripy/pull/1267) — fix: use correct name on joining group hab (1.2.x)

#### Closed issues

- [WebOfTrust #1160](https://github.com/WebOfTrust/keripy/issues/1160) — kli admit fails when issuer of credential has no witness

### 1.2.11 (2026-02-17 — historical milestone; not published to PyPI)

Tag [`1.2.11`](https://github.com/WebOfTrust/keripy/tree/1.2.11) targets [`5a5e8c52a8ea`](https://github.com/WebOfTrust/keripy/commit/5a5e8c52a8ea9f5beb8155b64773ca9ed2f0f668).

#### Highlights

- Recorded the completed GLEIF maintenance state under 1.2.11 without additional functional changes.
- This was a signed historical maintenance milestone, not a PyPI publication.

#### Direct changes

- Bump package metadata to 1.2.11.

#### Merged pull requests

- No merged pull request was identified; the changes above were committed directly to the maintenance line.

#### Closed issues

- No separately closed issue was identified for this release boundary.

### 1.2.10 (2026-02-17 — historical milestone; not published to PyPI)

Tag [`1.2.10`](https://github.com/WebOfTrust/keripy/tree/1.2.10) targets [`3b9725987ad7`](https://github.com/WebOfTrust/keripy/commit/3b9725987ad77f394db84eb2f33390e193c77064).

#### Highlights

- Added remaining escrow operations and metrics, configurable tocks, witness AID allowlists, inspection tooling, and multisig delegation/join repairs.
- This was a signed historical maintenance milestone, not a PyPI publication.

#### Merged pull requests

- [GLEIF-IT #17](https://github.com/GLEIF-IT/keripy/pull/17) — feat: get aid allowlists from witness config file
- [GLEIF-IT #18](https://github.com/GLEIF-IT/keripy/pull/18) — adds remaining escrows
- [GLEIF-IT #19](https://github.com/GLEIF-IT/keripy/pull/19) — adds escrow clear
- [GLEIF-IT #21](https://github.com/GLEIF-IT/keripy/pull/21) — export escrow metrics
- [GLEIF-IT #23](https://github.com/GLEIF-IT/keripy/pull/23) — config tocks
- [GLEIF-IT #29](https://github.com/GLEIF-IT/keripy/pull/29) — Fix multisig delegation with type guard and widened prefix check
- [GLEIF-IT #30](https://github.com/GLEIF-IT/keripy/pull/30) — Fix multisig join by using the icp ked, not the exn ked
- [GLEIF-IT #33](https://github.com/GLEIF-IT/keripy/pull/33) — fix: delegator seal storage; test temp=True fix for cf

#### Closed issues

- No separately closed issue was identified for this release boundary.

### 1.2.9 (2025-09-08 — historical milestone; not published to PyPI)

Tag [`1.2.9`](https://github.com/WebOfTrust/keripy/tree/1.2.9) targets [`93e8a791e237`](https://github.com/WebOfTrust/keripy/commit/93e8a791e237a9ab8e7980c998709669d7c28a7c).

#### Highlights

- Consolidated the GLEIF 1.2.7/1.2.8 maintenance line and corrected exchange-message escrow logging after an interim revert.
- This was a signed historical maintenance milestone, not a PyPI publication.

#### Merged pull requests

- [GLEIF-IT #5](https://github.com/GLEIF-IT/keripy/pull/5) — Branch 1 2 7 with all changes
- [GLEIF-IT #6](https://github.com/GLEIF-IT/keripy/pull/6) — fix: match dig or edig type to db function return type
- [GLEIF-IT #7](https://github.com/GLEIF-IT/keripy/pull/7) — chore: add new tag for escrow logging fix
- [GLEIF-IT #8](https://github.com/GLEIF-IT/keripy/pull/8) — Escrow logging error fix gleif 1 2 8
- [GLEIF-IT #9](https://github.com/GLEIF-IT/keripy/pull/9) — Revert "Escrow logging error fix gleif 1 2 8"
- [GLEIF-IT #10](https://github.com/GLEIF-IT/keripy/pull/10) — Escrow logging error fix gleif 1 2 8

#### Closed issues

- No separately closed issue was identified for this release boundary.

### 1.2.8 (2026-02-25 — historical milestone; not published to PyPI)

Tag [`1.2.8`](https://github.com/WebOfTrust/keripy/tree/1.2.8) targets [`6e162bfd229e`](https://github.com/WebOfTrust/keripy/commit/6e162bfd229ea977f075e785b0bca9ac038cf6fd).

#### Highlights

- Integrated the preceding GLEIF 1.2 maintenance work into WebOfTrust, including configurable database sizes and scheduler tocks, escrow metrics and tooling, witness allowlists, multisig delegation fixes, and compatibility repairs.
- This was a signed historical maintenance milestone, not a PyPI publication.

#### Merged pull requests

- [WebOfTrust #1089](https://github.com/WebOfTrust/keripy/pull/1089) — chore: bump version to 1.2.7
- [WebOfTrust #1093](https://github.com/WebOfTrust/keripy/pull/1093) — env only approach to configuring db sizes.
- [WebOfTrust #1154](https://github.com/WebOfTrust/keripy/pull/1154) — V1.2.7 runner
- [WebOfTrust #1155](https://github.com/WebOfTrust/keripy/pull/1155) — Add kli contacts commands
- [WebOfTrust #1165](https://github.com/WebOfTrust/keripy/pull/1165) — fix: provide issuer prefix for telquery on admit
- [WebOfTrust #1113](https://github.com/WebOfTrust/keripy/pull/1113) — fix: allow tests to use temp=True properly for Configer
- [WebOfTrust #1111](https://github.com/WebOfTrust/keripy/pull/1111) — fix: remove dip and drt from escrows once approved
- [WebOfTrust #1114](https://github.com/WebOfTrust/keripy/pull/1114) — fix: backport multisig delegation fixes from main
- [WebOfTrust #1110](https://github.com/WebOfTrust/keripy/pull/1110) — fix: multisig join should use icp ked not exn ked
- [WebOfTrust #1112](https://github.com/WebOfTrust/keripy/pull/1112) — docs: clean up and add agenting docs
- [WebOfTrust #1227](https://github.com/WebOfTrust/keripy/pull/1227) — config tocks
- [WebOfTrust #1228](https://github.com/WebOfTrust/keripy/pull/1228) — Enc/escrow metrics
- [WebOfTrust #1229](https://github.com/WebOfTrust/keripy/pull/1229) — adds escrow clear
- [WebOfTrust #1230](https://github.com/WebOfTrust/keripy/pull/1230) — feat: get aid allowlists from witness config file
- [WebOfTrust #1231](https://github.com/WebOfTrust/keripy/pull/1231) — Escrow logging error fix gleif 1 2 8
- [WebOfTrust #1232](https://github.com/WebOfTrust/keripy/pull/1232) — fix: match dig or edig type to db function return type
- [WebOfTrust #1233](https://github.com/WebOfTrust/keripy/pull/1233) — Rp missing field compat
- [WebOfTrust #1234](https://github.com/WebOfTrust/keripy/pull/1234) — bump version to 1.2.8
- [WebOfTrust #1235](https://github.com/WebOfTrust/keripy/pull/1235) — fix: delegator seal storage
- [WebOfTrust #1236](https://github.com/WebOfTrust/keripy/pull/1236) — adds a clean and inspect command
- [WebOfTrust #1237](https://github.com/WebOfTrust/keripy/pull/1237) — export escrow metrics

#### Closed issues

- [WebOfTrust #1160](https://github.com/WebOfTrust/keripy/issues/1160) — kli admit fails when issuer of credential has no witness

### 1.2.7 (2025-09-11)

Tag [`1.2.7`](https://github.com/WebOfTrust/keripy/tree/1.2.7) targets [`9d048c79042e`](https://github.com/WebOfTrust/keripy/commit/9d048c79042ef2895d1b1f2dc8c9c93f07443cc9). PyPI sdist SHA-256: `9e2687df544b2bc07ec2d63fa2fe906e8e8ab20bd5b788279da35724e443a223`.

#### Highlights

- Updated Doer signatures for HIO multiprocessing safety.
- Corrected export behavior, imports, and an exchange-message indentation error.

#### Merged pull requests

- [WebOfTrust #964](https://github.com/WebOfTrust/keripy/pull/964) — fix export
- [WebOfTrust #1004](https://github.com/WebOfTrust/keripy/pull/1004) — fixes imports
- [WebOfTrust #968](https://github.com/WebOfTrust/keripy/pull/968) — Update Doer method signatures to support new Hio multiprocessing safety
- [WebOfTrust #1083](https://github.com/WebOfTrust/keripy/pull/1083) — fix: correct indentation

#### Closed issues

- No separately closed issue was identified for this release boundary.

### 1.2.6 (2025-04-14)

Tag [`1.2.6`](https://github.com/WebOfTrust/keripy/tree/1.2.6) targets [`1d02a1dbe6a3`](https://github.com/WebOfTrust/keripy/commit/1d02a1dbe6a35e139c129791779a05468522e4bd). PyPI sdist SHA-256: `15a00b4d3014795a817e05e39495629894eb086c2d65647b275adbce42c116b0`.

#### Highlights

- Pinned HIO and corrected the package version metadata to 1.2.6.

#### Direct changes

- Pin HIO and correct the 1.2.6 version metadata.

#### Merged pull requests

- No merged pull request was identified; the changes above were committed directly to the maintenance line.

#### Closed issues

- No separately closed issue was identified for this release boundary.

### 1.2.5 (2025-04-14)

Tag [`1.2.5`](https://github.com/WebOfTrust/keripy/tree/1.2.5) targets [`b1b7aa20ca5a`](https://github.com/WebOfTrust/keripy/commit/b1b7aa20ca5a0cc4b911e5c07bdc9c3541a2a15e). PyPI sdist SHA-256: `2061e05e8c03bd261c0095e10a456867eab316f8668dbd0f10fde25bfeebea76`.

#### Highlights

- Expanded escrow administration and observability, including Reger clearing, Suber counting, trace logging, and logging fixes.
- Added notification listing and preserved existing contact data when resolving an OOBI again.

#### Merged pull requests

- [WebOfTrust #932](https://github.com/WebOfTrust/keripy/pull/932) — to 1.2.4: Add trace logging and consistent logging
- [WebOfTrust #940](https://github.com/WebOfTrust/keripy/pull/940) — adds a naive count all to SuberBase
- [WebOfTrust #942](https://github.com/WebOfTrust/keripy/pull/942) — fix: merge instead of replace contact data on re-OOBI
- [WebOfTrust #947](https://github.com/WebOfTrust/keripy/pull/947) — kli list notifications
- [WebOfTrust #951](https://github.com/WebOfTrust/keripy/pull/951) — adds escrow clear for reger
- [WebOfTrust #959](https://github.com/WebOfTrust/keripy/pull/959) — fix logging substitution error

#### Closed issues

- No separately closed issue was identified for this release boundary.

### 1.2.4 (2025-01-20)

Tag [`1.2.4`](https://github.com/WebOfTrust/keripy/tree/1.2.4) targets [`e5dbdc053674`](https://github.com/WebOfTrust/keripy/commit/e5dbdc05367482655ff38fb733cb479de7375765). PyPI sdist SHA-256: `ed74beeea63e86841c5a7244278f8bf29d8ba50bc33ece3d66ea15cb8c98ebaa`.

#### Highlights

- Added command support for clearing escrows.

#### Merged pull requests

- [WebOfTrust #926](https://github.com/WebOfTrust/keripy/pull/926) — adds escrow clear

#### Closed issues

- No separately closed issue was identified for this release boundary.

### 1.2.3 (2025-01-13)

Tag [`1.2.3`](https://github.com/WebOfTrust/keripy/tree/1.2.3) targets [`3a7ba5e1eaa6`](https://github.com/WebOfTrust/keripy/commit/3a7ba5e1eaa651004cb5db27ce0fd3eaea5d444b). PyPI sdist SHA-256: `c37e17f42f25bd04bc6b4e4c7787c645b93198255b508b038ab494034ff70801`.

#### Highlights

- Added a witness query endpoint for retrieving an AID's TEL events.

#### Merged pull requests

- [WebOfTrust #887](https://github.com/WebOfTrust/keripy/pull/887) — feat: add endpoint in witness to query tel event of an aid

#### Closed issues

- [WebOfTrust #672](https://github.com/WebOfTrust/keripy/issues/672) — get cred events from an issuer's TEL?

### 1.2.2 (2025-01-02)

Tag [`1.2.2`](https://github.com/WebOfTrust/keripy/tree/1.2.2) targets [`60ef7489cd12`](https://github.com/WebOfTrust/keripy/commit/60ef7489cd12e95b785064853ac691973c73ad29). PyPI sdist SHA-256: `aff8a3f53e95c238b1658e1b2f9b9a5430b97cfab44ed7baff0b7f0625c465c2`.

#### Highlights

- Corrected command-line argument handling.

#### Merged pull requests

- [WebOfTrust #918](https://github.com/WebOfTrust/keripy/pull/918) — fixes command line args

#### Closed issues

- No separately closed issue was identified for this release boundary.

### 1.2.1 (2024-12-14)

Tag [`1.2.1`](https://github.com/WebOfTrust/keripy/tree/1.2.1) targets [`69fe0fce1daa`](https://github.com/WebOfTrust/keripy/commit/69fe0fce1daac4a875392ac64701623d484a6a52). PyPI sdist SHA-256: `7f4620c2ca8bd3c85ec9c613c459533242181010910aefc33b3422ab3003358a`.

#### Highlights

- Passed salts and nonces through credential creation so private multisig credential workflows can be driven from the command line.
- Updated type hints across the codebase.

#### Direct changes

- Pass salts and nonces through `kli vc create` for private multisig credentials.
- Update type hints.

#### Merged pull requests

- No merged pull request was identified; the changes above were committed directly to the maintenance line.

#### Closed issues

- No separately closed issue was identified for this release boundary.

### 1.2.0 (2024-11-18)

Tag [`1.2.0`](https://github.com/WebOfTrust/keripy/tree/1.2.0) targets [`31d985d482d2`](https://github.com/WebOfTrust/keripy/commit/31d985d482d2cb7c340dfe52ef8554de06f7ed02). PyPI sdist SHA-256: `42398da1d44e5dc43908f97dabe6afbc74a37c31f3cee8f81512283a92e3b597`.

#### Highlights

- Established the 1.2 maintenance series with broad CLI, witness, delegation, multisig, credential, database, parser, and documentation work accumulated since 1.1.17.
- Included the KERI 1.2 dependency and packaging transition and the associated compatibility and test updates.

#### Merged pull requests

- [WebOfTrust #661](https://github.com/WebOfTrust/keripy/pull/661) — Fixed spelling typo in help text for --no-backers
- [WebOfTrust #660](https://github.com/WebOfTrust/keripy/pull/660) — Updated build-witness-demo command.  No gleif/keri-1.1.0 on dockerhub…
- [WebOfTrust #671](https://github.com/WebOfTrust/keripy/pull/671) — Use image python:3.10-alpine; Fix docker COPY build failure
- [WebOfTrust #677](https://github.com/WebOfTrust/keripy/pull/677) — Revert "Use image python:3.10-alpine; Fix docker COPY build failure"
- [WebOfTrust #679](https://github.com/WebOfTrust/keripy/pull/679) — Update to Python 3.12.1
- [WebOfTrust #680](https://github.com/WebOfTrust/keripy/pull/680) — Superseding Delegated Rotation and misfit escrow
- [WebOfTrust #683](https://github.com/WebOfTrust/keripy/pull/683) — Support for nested fractional weight sets as value of top level weight
- [WebOfTrust #684](https://github.com/WebOfTrust/keripy/pull/684) — Added support for Texter Class for variable length text (bytes) with …
- [WebOfTrust #685](https://github.com/WebOfTrust/keripy/pull/685) — refactor of some Texter method more tests.
- [WebOfTrust #686](https://github.com/WebOfTrust/keripy/pull/686) — Refactor smell so can be upgraded to version string 1.X and 2.X
- [WebOfTrust #687](https://github.com/WebOfTrust/keripy/pull/687) — refactor sniff to be in kering instead of Parser class method. This i…
- [WebOfTrust #682](https://github.com/WebOfTrust/keripy/pull/682) — fix cloneCreds usage of cloneTvtAt to be consistent with grant, etc. …
- [WebOfTrust #689](https://github.com/WebOfTrust/keripy/pull/689) — Refactor remove hard coded field label tests now superseded by Serder.verify which does versioned field label tests
- [WebOfTrust #688](https://github.com/WebOfTrust/keripy/pull/688) — Add loglevel as a command line argument for witness
- [WebOfTrust #692](https://github.com/WebOfTrust/keripy/pull/692) — fixed typos and formatting
- [WebOfTrust #693](https://github.com/WebOfTrust/keripy/pull/693) — Version2 version string support in versify deversify and smell
- [WebOfTrust #695](https://github.com/WebOfTrust/keripy/pull/695) — This hotfix adds fixes for rotation from kli and witness arg for logging
- [WebOfTrust #704](https://github.com/WebOfTrust/keripy/pull/704) — Some doc string clean up and test stubb for smell with merge
- [WebOfTrust #705](https://github.com/WebOfTrust/keripy/pull/705) — Includes 2 fixes
- [WebOfTrust #701](https://github.com/WebOfTrust/keripy/pull/701) — Non deterministic prefixes in witnesses
- [WebOfTrust #706](https://github.com/WebOfTrust/keripy/pull/706) — More preparatory work for versioned Serders
- [WebOfTrust #708](https://github.com/WebOfTrust/keripy/pull/708) — clean up code. when d is dict list(d) == list(d.keys(0)) so replace t…
- [WebOfTrust #710](https://github.com/WebOfTrust/keripy/pull/710) — Support with tests for alls, opts, alts, strict and extras when not strict for fields for message types for Serder
- [WebOfTrust #709](https://github.com/WebOfTrust/keripy/pull/709) — Removed dead "kli agent start" command from README
- [WebOfTrust #712](https://github.com/WebOfTrust/keripy/pull/712) — Refactor better support for versioning for Serder
- [WebOfTrust #713](https://github.com/WebOfTrust/keripy/pull/713) — makify now ensures correct ordering of all fields
- [WebOfTrust #714](https://github.com/WebOfTrust/keripy/pull/714) — added .verify attribute to SuberBase so that subclasses can init to r…
- [WebOfTrust #715](https://github.com/WebOfTrust/keripy/pull/715) — Added CESR as serialization kind prapatory to cesr native messages
- [WebOfTrust #717](https://github.com/WebOfTrust/keripy/pull/717) — Added support for tag parameter to Counter, Added b64ToVer static met…
- [WebOfTrust #718](https://github.com/WebOfTrust/keripy/pull/718) — Updated Code Tables for Version 2.0 Count Codes. NOrmalized codex labels between versions 1 and 2
- [WebOfTrust #721](https://github.com/WebOfTrust/keripy/pull/721) — Refactoring Cleanup for versioning support
- [WebOfTrust #722](https://github.com/WebOfTrust/keripy/pull/722) — More refactoring in support of CESR native serilaizations
- [WebOfTrust #719](https://github.com/WebOfTrust/keripy/pull/719) — Removed watcher commands from keripy
- [WebOfTrust #720](https://github.com/WebOfTrust/keripy/pull/720) — ensure creder.attrib is not a string before treating it like a dict
- [WebOfTrust #723](https://github.com/WebOfTrust/keripy/pull/723) — Catching socket exception when creating witness http client
- [WebOfTrust #728](https://github.com/WebOfTrust/keripy/pull/728) — Refactor Matter to support efficient encoding of short Base64 values for field tags, types, traits, etc
- [WebOfTrust #729](https://github.com/WebOfTrust/keripy/pull/729) — Refined functionality of Matter so supports special soft part of code for both empty and not empty raw when fixed code.
- [WebOfTrust #730](https://github.com/WebOfTrust/keripy/pull/730) — Fixed refined logic to fix bugs in corner cases. Updated comments add…
- [WebOfTrust #731](https://github.com/WebOfTrust/keripy/pull/731) — Refactor clean simplify fix Matter._exfil ._bexfil with more tests support for special soft codes
- [WebOfTrust #732](https://github.com/WebOfTrust/keripy/pull/732) — Tagger class and Refactor Verser to be subclass of Tagger
- [WebOfTrust #734](https://github.com/WebOfTrust/keripy/pull/734) — New database tables for tracking Habs and multisig participants.
- [WebOfTrust #735](https://github.com/WebOfTrust/keripy/pull/735) — added Ilker class and started tests for native CESR Serder some cleanup refactor
- [WebOfTrust #737](https://github.com/WebOfTrust/keripy/pull/737) — Writing logs into file is configurable from cli argument
- [WebOfTrust #736](https://github.com/WebOfTrust/keripy/pull/736) — updates codecov adds secret
- [WebOfTrust #740](https://github.com/WebOfTrust/keripy/pull/740) — Updated docker images to use python 3.12
- [WebOfTrust #741](https://github.com/WebOfTrust/keripy/pull/741) — Move Indexer and its subclasses to its own module. Put common Matter and Indexer classing in keri.core package .__init__
- [WebOfTrust #742](https://github.com/WebOfTrust/keripy/pull/742) — Update to contact list to account for non-backward compatible changes
- [WebOfTrust #743](https://github.com/WebOfTrust/keripy/pull/743) — Added Structor and Sealer classes with tests. Some refactoring cleanup.
- [WebOfTrust #744](https://github.com/WebOfTrust/keripy/pull/744) — fixed typo in counting Counter Codex table
- [WebOfTrust #746](https://github.com/WebOfTrust/keripy/pull/746) — Fix failing EndRole escrow
- [WebOfTrust #745](https://github.com/WebOfTrust/keripy/pull/745) — update comments and help texts referring to 22 character passcode
- [WebOfTrust #750](https://github.com/WebOfTrust/keripy/pull/750) — Secure Witness Support
- [WebOfTrust #751](https://github.com/WebOfTrust/keripy/pull/751) — Basic support for CESR native serialization of some KERI event messages
- [WebOfTrust #756](https://github.com/WebOfTrust/keripy/pull/756) — Support legacy format for Numbers (seqquenc numbers) in Seals as hex strs not qb64.
- [WebOfTrust #757](https://github.com/WebOfTrust/keripy/pull/757) — Added support for Serder.makify and .verify for CESR native keri
- [WebOfTrust #755](https://github.com/WebOfTrust/keripy/pull/755) — Logging updates
- [WebOfTrust #758](https://github.com/WebOfTrust/keripy/pull/758) — Added support for Rotation event CESR native with test
- [WebOfTrust #754](https://github.com/WebOfTrust/keripy/pull/754) — 690 Fix SyntaxWarning: invalid escape sequence
- [WebOfTrust #759](https://github.com/WebOfTrust/keripy/pull/759) — Added tests an size comparisons for delcept and deltate for CESR Native serialization
- [WebOfTrust #760](https://github.com/WebOfTrust/keripy/pull/760) — added streaming.py and test_streaming.py preliminary setup for annota…
- [WebOfTrust #765](https://github.com/WebOfTrust/keripy/pull/765) — Update Contributing.md
- [WebOfTrust #770](https://github.com/WebOfTrust/keripy/pull/770) — Attempt to conditionally run `brew install libsodium` on macos-latest build
- [WebOfTrust #761](https://github.com/WebOfTrust/keripy/pull/761) — Fixed missing verbose output from ipex list
- [WebOfTrust #769](https://github.com/WebOfTrust/keripy/pull/769) — issue templates
- [WebOfTrust #768](https://github.com/WebOfTrust/keripy/pull/768) — Deprecate randomNonce() and refactor using Salter().qb64
- [WebOfTrust #771](https://github.com/WebOfTrust/keripy/pull/771) — Changes from IIW plus fix typo in count code table 2.0
- [WebOfTrust #772](https://github.com/WebOfTrust/keripy/pull/772) — New introduce rpy handler and updates to create HTTP server
- [WebOfTrust #774](https://github.com/WebOfTrust/keripy/pull/774) — Fix multisig rotation
- [WebOfTrust #776](https://github.com/WebOfTrust/keripy/pull/776) — test: three stooges multisig rotate and interact
- [WebOfTrust #777](https://github.com/WebOfTrust/keripy/pull/777) — fix: stooge AID Prefixes and run in test_scripts.sh
- [WebOfTrust #778](https://github.com/WebOfTrust/keripy/pull/778) — Remove generateSigners function and refactor with Salter().signers()
- [WebOfTrust #780](https://github.com/WebOfTrust/keripy/pull/780) — removes bran from GroupMultisigRotate constructor inplace of an existing Habery
- [WebOfTrust #783](https://github.com/WebOfTrust/keripy/pull/783) — feat: multisig join --group arg
- [WebOfTrust #784](https://github.com/WebOfTrust/keripy/pull/784) — Updates to delegation processing to fix delegation.
- [WebOfTrust #786](https://github.com/WebOfTrust/keripy/pull/786) — Add processing method for delegables escrow in Kevery
- [WebOfTrust #789](https://github.com/WebOfTrust/keripy/pull/789) — fixes MissingDelegableApprovalError logging bug
- [WebOfTrust #790](https://github.com/WebOfTrust/keripy/pull/790) — cleans up some usage of coring.serder
- [WebOfTrust #791](https://github.com/WebOfTrust/keripy/pull/791) — updates dockerfile to new alpine
- [WebOfTrust #797](https://github.com/WebOfTrust/keripy/pull/797) — fix: re-cue unmatched cues in Respondant
- [WebOfTrust #800](https://github.com/WebOfTrust/keripy/pull/800) — Add new script for revokable authorization
- [WebOfTrust #802](https://github.com/WebOfTrust/keripy/pull/802) — fix: correct short arg for --group from -a to -g
- [WebOfTrust #803](https://github.com/WebOfTrust/keripy/pull/803) — Many additions and fixes to kli commands, new ESSR payload attachment support
- [WebOfTrust #804](https://github.com/WebOfTrust/keripy/pull/804) — fix grouping multisig parser to process events in local mode
- [WebOfTrust #805](https://github.com/WebOfTrust/keripy/pull/805) — New and updated kli commands for witnesss, watchers and mailboxes.  Delegation fixes
- [WebOfTrust #798](https://github.com/WebOfTrust/keripy/pull/798) — fix alias renaming
- [WebOfTrust #808](https://github.com/WebOfTrust/keripy/pull/808) — Fixes to `watcher add` command
- [WebOfTrust #809](https://github.com/WebOfTrust/keripy/pull/809) — fix: add smids group hab call
- [WebOfTrust #810](https://github.com/WebOfTrust/keripy/pull/810) — Externalize the size limit for LMDB map size for Baser to an environment variable.
- [WebOfTrust #812](https://github.com/WebOfTrust/keripy/pull/812) — Fixed KERI_BASER_MAP_SIZE not integer bug.
- [WebOfTrust #815](https://github.com/WebOfTrust/keripy/pull/815) — Update to latest Hio build and new kli command
- [WebOfTrust #817](https://github.com/WebOfTrust/keripy/pull/817) — New kli command for introductions and a few fixes
- [WebOfTrust #822](https://github.com/WebOfTrust/keripy/pull/822) — updates Hio version
- [WebOfTrust #826](https://github.com/WebOfTrust/keripy/pull/826) — Now uses versioned Counter class in core.counting everywhere. Old unversioned coring.Counter has been removed.
- [WebOfTrust #828](https://github.com/WebOfTrust/keripy/pull/828) — Support for xs field (xtra prepad) for special soft part codes. Tagger no longer has to kludge prepad.
- [WebOfTrust #829](https://github.com/WebOfTrust/keripy/pull/829) — refactor streamlined xtra xs field support in Matter
- [WebOfTrust #830](https://github.com/WebOfTrust/keripy/pull/830) — Support for variable sized raw in Cipher with unit tests
- [WebOfTrust #836](https://github.com/WebOfTrust/keripy/pull/836) — Updated Encrypter, Decrypter, and Cipher to support all Cipher types including variable length with unit tests.
- [WebOfTrust #839](https://github.com/WebOfTrust/keripy/pull/839) — Refactor all Prefixer derive and verify functionality is now part of Serder and SerderKERI
- [WebOfTrust #840](https://github.com/WebOfTrust/keripy/pull/840) — Refactor Diger and classes to benefit from refactor. More DRY
- [WebOfTrust #843](https://github.com/WebOfTrust/keripy/pull/843) — Labeler as Matter subclass for compact field map labels that support all sizes   with unit tests
- [WebOfTrust #832](https://github.com/WebOfTrust/keripy/pull/832) — adds docker support for multiple architectures
- [WebOfTrust #838](https://github.com/WebOfTrust/keripy/pull/838) — Adjusted help text for escrow/kevers to better match their intended functionality
- [WebOfTrust #841](https://github.com/WebOfTrust/keripy/pull/841) — feat: raise MissingEntryError for missing credential
- [WebOfTrust #827](https://github.com/WebOfTrust/keripy/pull/827) — Fix notes datetime ISO 8601 format
- [WebOfTrust #844](https://github.com/WebOfTrust/keripy/pull/844) — 2 fixes for delegation:
- [WebOfTrust #848](https://github.com/WebOfTrust/keripy/pull/848) — Update sequence number querying for logs
- [WebOfTrust #849](https://github.com/WebOfTrust/keripy/pull/849) — Replaced qnfs db with subing.IoSetSuber
- [WebOfTrust #851](https://github.com/WebOfTrust/keripy/pull/851) — Fixes for anchoring multiple delegates in a single delegator event, exn escrow timeout.
- [WebOfTrust #859](https://github.com/WebOfTrust/keripy/pull/859) — Extensive changes to the delegation validation and escrow logic. Extensive refactoring of the classes in subing.py
- [WebOfTrust #860](https://github.com/WebOfTrust/keripy/pull/860) — Some clean up refactoring to use fleshed out OnIoDupSuber methods for pdes escrow
- [WebOfTrust #861](https://github.com/WebOfTrust/keripy/pull/861) — Minor update to parsing ESSR attachments.
- [WebOfTrust #858](https://github.com/WebOfTrust/keripy/pull/858) — fix: update smids and rmids for group lead on new event
- [WebOfTrust #871](https://github.com/WebOfTrust/keripy/pull/871) — Two command line changes:
- [WebOfTrust #873](https://github.com/WebOfTrust/keripy/pull/873) — Fix calls to out of order escrow
- [WebOfTrust #875](https://github.com/WebOfTrust/keripy/pull/875) — feat: migrations for 0.6.7 to 1.2.0
- [WebOfTrust #890](https://github.com/WebOfTrust/keripy/pull/890) — Last bit of clean up for V1.2.0 rc4

#### Closed issues

- [WebOfTrust #764](https://github.com/WebOfTrust/keripy/issues/764) — Outdated Discord Invitation Link
- [WebOfTrust #785](https://github.com/WebOfTrust/keripy/issues/785) — Add a processing loop for delegables escrow
- [WebOfTrust #787](https://github.com/WebOfTrust/keripy/issues/787) — MissingDelegableApprovalError logging bug
- [WebOfTrust #811](https://github.com/WebOfTrust/keripy/issues/811) — KERI_BASER_MAP_SIZE isn't an integer tests fail
- [WebOfTrust #842](https://github.com/WebOfTrust/keripy/issues/842) — current main branch regression: KEL of a delegated `aid` lacks `source seal couples`
