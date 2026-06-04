# Root + GARs delegated multisig reproducer

Recreates a production scenario where Root (delegator, multisig) was on KERIpy 1.1.x,
from GARs (delegate, multisig) still on 1.1.x.

The script is split across the upgrade boundary because citadel's migration
does not rewrite escrow sub-db keys (`pdes`, `udes`, etc.) from the 1.1.x
plain-prefix format to the 1.2.x `<prefix>.<sn_hex>` format. Running the drt
send before migration leaves entries citadel can't read.

## Phases

| Phase | Script                       | Run under     | Notes |
|-------|------------------------------|---------------|-------|
| A     | `setup-root-gars.sh`         | kli 1.1.4x    | Creates Root + GARs, anchors GARs inception. Exits quiescent. |
| B     | (manual)                     | citadel 1.2.x | Open root1/root2; let citadel migrate. |
| C     | `rotate-gars.sh`             | kli 1.1.4x    | Rotates GAR locals, dispatches the drt, then stops the rotate processes — GARs left pending at sn=0. |
| D     | (citadel UI)                 | citadel 1.2.x | Approve the drt; citadel anchors it in Root's KEL. |
| E     | `finalize-gars-rotation.sh`  | kli 1.1.4x    | gar1/gar2 pull the anchor and commit GARs at sn=1. |

## Prerequisites

```
source scripts/demo/demo-scripts.sh
kli witness demo                       # in another terminal
rm -rf ~/.keri /usr/local/var/keri/*   # clean slate
```

All keystores use passcode `DoB26Fj4x9LboAFWJra17O` (override via `PASSCODE` env var).

## AIDs (deterministic, hardcoded)

```
root1 local    : EF11YNn4i0r0dX1KNrWs_ATQH878L3blwCMOSgwQVi57
root2 local    : ENBdaRLJH7JOBAZo6aZbXelFP_I9yMd-RFrJ6pJ7V3CY
gar1  local    : EM0Di_wQZhUA0uKsR0gC0bSnOxcroCX-JbUuX9TBcvA1
gar2  local    : EA7cQdIZoCoQGWbjdVQYBVo4aNURsQml-vnEV8RMaSIG
Root  multisig : EG0TRj_O4kAelbdtvLlYviu6uoQFkiDn3I4kTwA7odzx
GARs  multisig : EH7-jpsut3LXxo0wwUubLp4F8goX84CaWsL-H34Je_Od
```

Change any salt, witness, or threshold and these (plus the `aids`/`delpre`
in `data/multisig-root.json` and `data/multisig-gars.json`) must be regenerated.
