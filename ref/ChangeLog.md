# Change Log for keripy

## 2.0.0-dev5
### Backwards breaking interface changes
Changes to call signatures that will break dependent libraries

#### keri.app.delegating.py
Changed `complete(self, prefixer, seqner, diger=None)` to `complete(self, prefixer, number, diger=None)`.
Renamed `seqner` parameter to `number` to match the actual type (`Number`) being
passed. All callers in `rotate.py`, `incept.py`, and `grouping.py` updated.

## 2.0.0-dev5
### Backwards breaking interface changes
Changes to call signatures that will break dependent libraries

#### keri.core.eventing.Kevery.processEvent
Changed keyword parameter `delseqner` (Seqner) to `delnum` (Number) in the function
signature and all internal call sites. External callers that previously passed
`delseqner` must now pass `delnum` with a `Number` instance.

## 2.0.0-dev5
### Backwards breaking interface changes
Changes to call signatures that will break dependent libraries

#### keri.core.routing.Router.dispatch
Renamed keyword parameter `saider` to `diger` to reflect the actual type (`Diger`)
being passed. All registered route handler functions that receive this parameter via
the dispatch callback interface must update their signatures accordingly.

#### keri.core.routing.Revery.processReply
Renamed local variable `saider` to `diger` and updated the `dispatch(saider=)` call
site to `dispatch(diger=)`.

#### keri.core.routing.processRouteNotFound
Renamed keyword parameter `saider` to `diger`.

#### keri.core.eventing.Kevery.processReplyEndRole
Renamed keyword parameter `saider` to `diger`.

#### keri.core.eventing.Kevery.processReplyLocScheme
Renamed keyword parameter `saider` to `diger`.

#### keri.core.eventing.Kevery.processReplyKeyStateNotice
Renamed keyword parameter `saider` to `diger`. Renamed internal local variable
`diger` (derived from `ksr.d`) to `ksr_diger` to avoid shadowing the parameter.

#### keri.core.eventing.Kevery.processReplyAddWatched
Renamed keyword parameter `saider` to `diger`.

#### keri.app.oobiing.Oobiery.processReply
Renamed keyword parameter `saider` to `diger`.

#### keri.vdr.eventing.Tevery.processReplyRegistryTxnState
Renamed keyword parameter `saider` to `diger`. Removed the now-redundant
`diger = saider` alias line from the function body.

#### keri.vdr.eventing.Tevery.processReplyCredentialTxnState
Renamed keyword parameter `saider` to `diger`. Removed the now-redundant
`diger = saider` alias line from the function body.


## 2.0.0-dev1
### Backwards breaking interface changes
Changes to call signatures that will break dependent libraries

#### keri.help.helping.py
Changed nonStringIterable() to isNonStringIterable()
Change nonStringSequence() to isNonStringSequence()
Added Metaclasses NonStringIterable and NonStringSequence

#### keri.core.coring.py
Changed Pather class to support both relative and aboslute paths
Now supports relative paths in Base64 using excape sequence.
More thorough checks for valid paths.
Supports both paths for pathed material and paths for routes and return routes
in KERI messages.
Init supports path as '/' delimited string that if otherwise the path parts
are Based64 will compacting encode as StrB64 variable length. If not will encode as
Bytes variable length.
No longer is Pather a subclass of Bexter so .bext is no longer a property
.path property returns a path string this is a breaking change
.parts property returns a list of path parts as either relative or absolute depending
on what the actual path expression
.rparts property returns a list of path parts as a relative path
On init relative (bool) False forces path to be absolute Relative True allows
relative path if expressed as relative.
On init pathive(bool) True forces B64 compliant path parts
raises exception if not. False allows non B64 path parts.

Changed Dicter Class. made randomNonce a statice method. ._randomNonce instead
of module method since only used inside Dicter
Changed init parameter sad to dicter since more accurate.

#### keri.core.serdering.SerderACDC
Changed .regi property to .regid  to avoid confusion with regd regk and other reg
and to avoid the confusion of i meaning a AID, whereas regid is a said
its an identifier for registry but not an aid.  Since regd is already
used to mean something else, we picked the regid which was not previously
used anywhere.

#### keri.core.streaming now keri.core.annotating
Due to circular imports moved Streamer class to keri.core.signing  and
renamed streaming.py and test_streaming.py to annotating.py and test_annotating
from keri.core import Streamer still works.

#### keri.core Tierage and Tiers
moved Tierage and Tiers defintions from keri.core.coring to keri.core.signing
where they more naturally belong (not used in coring)
from keri.core import Tiers still works
