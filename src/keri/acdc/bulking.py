# -*- encoding: utf-8 -*-
"""
Experimental helpers for shared-registry bulk-issued private ACDCs.

"""

from collections.abc import Mapping

from ..core import Diger, Noncer, Salter, SerderACDC
from ..core.coring import MtrDex, NonceDex
from ..kering import InvalidValueError, KeriError, MisbindingError
from . import regeventing


class BulkDeriver:
    """Derive one bulk set's UUIDs and blinding factors from a shared salt."""

    def __init__(self, salt, *, temp=False):
        """Create a bulk-set derivation context from raw shared-salt bytes."""
        if not isinstance(salt, (bytes, bytearray)) or len(salt) != 16:
            raise InvalidValueError("bulk salt must be exactly 16 raw bytes")
        self.salter = Salter(raw=salt)
        self.temp = temp

    @staticmethod
    def _index(index):
        """Render a non-negative numeric path index as unpadded lowercase hex."""
        if isinstance(index, bool) or not isinstance(index, int) or index < 0:
            raise InvalidValueError(f"invalid bulk derivation index {index!r}")
        return f"{index:x}"

    def _nonce(self, path):
        """Derive one 256-bit salty nonce at ``path``."""
        raw = self.salter.stretch(size=32, path=path, temp=self.temp)
        return Noncer(raw=raw, code=NonceDex.Salt_256).qb64

    def u(self, k, j=None):
        """Derive copy ``k``'s top-level or nested-block UUID."""
        path = self._index(k)
        if j is not None:
            path = f"{path}/{self._index(j)}"
        return self._nonce(path)

    def v(self, k):
        """Derive copy ``k``'s blinding factor in the distinct ``k.`` space."""
        return self._nonce(f"{self._index(k)}.")


def _blindSaid(blinding, said):
    """Return ``b_k = H(v_k || d_k)`` under the encoding rules."""
    if not isinstance(blinding, str) or not isinstance(said, str):
        raise InvalidValueError("bulk blinding factors and ACDC SAIDs must be qb64 text")
    try:
        noncer = Noncer(qb64=blinding)
        diger = Diger(qb64=said)
    except KeriError as ex:
        raise InvalidValueError("invalid bulk blinding factor or ACDC SAID") from ex
    if noncer.qb64 != blinding or noncer.code != NonceDex.Salt_256:
        raise InvalidValueError(f"invalid bulk blinding factor code {noncer.code}")
    if diger.qb64 != said:
        raise InvalidValueError("invalid bulk ACDC SAID")
    return Diger(ser=(blinding + said).encode(), code=MtrDex.Blake3_256).qb64


def _aggregateMembers(members):
    """Return the Blake3-256 digest of an ordered qb64 blinded-member list."""
    if not members:
        raise InvalidValueError("bulk commitment requires at least one member")
    for member in members:
        if not isinstance(member, str):
            raise InvalidValueError("bulk members must be qb64 digest text")
        try:
            diger = Diger(qb64=member)
        except KeriError as ex:
            raise InvalidValueError("invalid bulk member digest") from ex
        if diger.qb64 != member or diger.code != MtrDex.Blake3_256:
            raise InvalidValueError(f"invalid bulk member digest code {diger.code}")
    return Diger(ser="".join(members).encode(), code=MtrDex.Blake3_256).qb64


def makeCommitment(blindings, saids):
    """Build the ordered blinded-member tuple and aggregate commitment ``B``."""
    try:
        blindings = tuple(blindings)
        saids = tuple(saids)
    except TypeError as ex:
        raise InvalidValueError("bulk commitment inputs must be iterable") from ex

    if not blindings or len(blindings) != len(saids):
        raise InvalidValueError("bulk commitment inputs must be non-empty and equally sized")

    members = tuple(_blindSaid(blinding, said) for blinding, said in zip(blindings, saids))
    return members, _aggregateMembers(members)


def verifyMembership(said, blinding, members, aggregate):
    """Return ``True`` only when ``said`` belongs to the committed blinded list."""
    try:
        members = tuple(members)

        # Validate the aggregate
        if not isinstance(aggregate, str):
            return False

        committed = Diger(qb64=aggregate)
        if committed.qb64 != aggregate or committed.code != MtrDex.Blake3_256:
            return False

        # Recompute the aggregate from the members and compare
        if _aggregateMembers(members) != aggregate:
            return False

        # Check if the said belongs to the members
        return _blindSaid(blinding, said) in members
    except (KeriError, AttributeError, TypeError, ValueError):
        return False


def parseProof(proof):
    """Validate and unpack one shared-list proof payload."""
    if (not isinstance(proof, Mapping) or
            set(proof) != {"blinding", "members"}):
        raise InvalidValueError("invalid shared-list proof shape")

    blinding = proof["blinding"]
    try:
        noncer = Noncer(qb64=blinding)
        members = tuple(proof["members"])
    except (KeriError, TypeError, ValueError) as ex:
        raise InvalidValueError("invalid IPEX shared-list proof") from ex

    if (not isinstance(blinding, str) or noncer.qb64 != blinding or
            noncer.code != NonceDex.Salt_256):
        raise InvalidValueError("invalid IPEX shared-list blinding factor")
    _aggregateMembers(members)
    return blinding, members


def vetSharedList(rip, updates=None, *, db, blinders, acdc, blinding,
                  members, sources=None):
    """Verify one ACDC against shared-registry bulk commitment evidence.

    The verifier receives only the selected ACDC's blinding factor, the public
    blinded-member list, and normal TEL/KEL evidence.  It never receives the
    shared derivation salt. The caller is responsible for supplying the TEL
    chain it intends to evaluate; this function does not discover newer events.
    """
    try:
        if not isinstance(acdc, SerderACDC):
            raw = acdc.encode() if isinstance(acdc, str) else bytes(acdc)
            acdc = SerderACDC(raw=raw)
        if not acdc.verify():
            raise MisbindingError(f"Presented bulk ACDC {acdc.said} is invalid.")
        ripper = regeventing.vetRip(rip)
        members = tuple(members)
        aggregate = _aggregateMembers(members)
    except MisbindingError:
        raise
    except (KeriError, AttributeError, TypeError, ValueError) as ex:
        raise MisbindingError("Invalid shared-list bulk evidence.") from ex

    issuer = acdc.sad.get("i")
    if issuer != ripper.sad["i"]:
        raise MisbindingError(f"Presented ACDC issuer {issuer} does not match "
                              f"bulk registry issuer {ripper.sad['i']}.")
    if acdc.sad.get("rd") != ripper.said:
        raise MisbindingError(f"Presented ACDC registry {acdc.sad.get('rd')} does "
                              f"not match bulk registry {ripper.said}.")
    try:
        member = _blindSaid(blinding, acdc.said)
    except (KeriError, AttributeError, TypeError, ValueError) as ex:
        raise MisbindingError("Invalid shared-list membership proof.") from ex
    if member not in members:
        raise MisbindingError(f"Presented ACDC {acdc.said} is not a member of "
                              f"bulk commitment {aggregate}.")

    record = regeventing.vetBinds(rip=ripper,
                                  updates=updates,
                                  db=db,
                                  blinders=blinders,
                                  target=aggregate,
                                  controller=issuer,
                                  sources=sources)

    return record._replace(binding="bulk")
