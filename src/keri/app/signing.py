# -*- encoding: utf-8 -*-
"""
KERI
keri.app.signing module

"""
from .. import Vrsn_1_0
from .habbing import GroupHab
from ..core import Pather, Counter, Seqner, Diger, Codens


def serialize(creder, prefixer, seqner, saider):
    """Serialize a credential with a seal source triple attachment.

    Appends a CESR-encoded SealSourceTriples counter followed by the
    prefixer, seqner, and saider to the raw credential bytes.

    Args:
        creder: Credential whose raw bytes form the base of the serialization.
        prefixer: Prefixer for the establishment event that seals the credential.
        seqner (Seqner): Sequence number of the sealing establishment event.
        saider (Saider): SAID of the sealing establishment event.

    Returns:
        bytes: Serialized credential bytes with the seal source triple appended.
    """
    craw = bytearray(creder.raw)
    craw.extend(Counter(Codens.SealSourceTriples, count=1,
                             version=Vrsn_1_0).qb64b)
    craw.extend(prefixer.qb64b)
    craw.extend(seqner.qb64b)
    craw.extend(saider.qb64b)

    return bytes(craw)


#def ratify(hab, serder, paths=None, pipelined=False):
    #""" Sign the SAD or SAIDs with the keys from the Habitat.

    #Sign the SADs or SAIDs of the SADs as identified by the paths.  If paths is
    #None, default to signing the root SAD only.

    #Parameters:
        #hab (Habitat): environment used to sign the SAD
        #serder (Union[Serder,Creder]): the self addressing data (SAD)
        #paths (list): list of paths specified as arrays of path components
        #pipelined (bool): True means prepend pipelining count code to attachemnts
            #False means to not prepend pipelining count code

    #Returns:
        #bytes: serialized SAD with qb64 CESR Proof Signature attachments

    #"""
    #paths = [[]] if paths is None else paths
    #sadsigers, sadcigars = signPaths(hab=hab, serder=serder, paths=paths)
    #return provision(serder, sadsigers=sadsigers, sadcigars=sadcigars, pipelined=pipelined)




#def provision(serder, *, sadsigers=None, sadcigars=None, pipelined=False):
    #"""
    #Attaches indexed signatures from sigers and/or cigars and/or wigers to
    #KERI message data from serder
    #Parameters:
        #serder (Union[Serder,Creder]): instance containing the event
        #sadsigers (list): of Siger instances (optional) to create indexed signatures
        #sadcigars (list): optional list of Cigars instances of non-transferable non indexed
            #signatures from  which to form receipt couples.
            #Each cigar.vefer.qb64 is pre of receiptor and cigar.qb64 is signature
        #pipelined (bool): True means prepend pipelining count code to attachemnts
            #False means to not prepend pipelining count code

    #Returns: bytearray SAD with CESR Proof Signature

    #"""
    #msg = bytearray(serder.raw)  # make copy into new bytearray so can be deleted
    #if not (sadsigers or sadcigars):
        #raise ValueError("Missing attached signatures on message = {}."
                         #"".format(serder.ked))

    #msg.extend(eventing.proofize(sadtsgs=sadsigers, sadcigars=sadcigars, pipelined=pipelined))
    #return msg


def signPaths(hab, serder, paths):
    """Sign the SAD or SAIDs identified by the given paths using the Habitat's keys.

    For each path, extracts the tail of the SAD at that path and signs it.
    Transferable identifiers produce indexed signatures (sadsigers); non-transferable
    identifiers produce non-indexed bare signatures (sadcigars).

    Args:
        hab (Habitat): Signing environment providing keys and identifier state.
        serder (Serder | Creder): Self-addressing data (SAD) to sign.
        paths (list[list]): List of path component lists identifying the SAD
            fields to sign. Each inner list contains the string components of
            one path (e.g. ``[["a", "i"], []]``).

    Returns:
        tuple[list, list]: A two-element tuple ``(sadsigers, sadcigars)`` where:

        - **sadsigers** (*list*) — Each entry is a tuple
          ``(pather, prefixer, seqner, saider, sigers)`` for transferable
          identifier signatures.
        - **sadcigars** (*list*) — Each entry is a tuple
          ``(pather, cigars)`` for non-transferable identifier signatures.
    """
    sadsigers = []
    sadcigars = []

    if hab.kever.prefixer.transferable:
        prefixer, seqner, saider, indices = transSeal(hab)
        for parts in paths:
            pather = Pather(parts=parts)
            data = pather.tail(serder=serder)

            sigers = hab.sign(ser=data,
                              verfers=hab.kever.verfers,
                              indexed=True)
            sadsigers.append((pather, prefixer, seqner, saider, sigers))

    else:
        for parts in paths:
            pather = Pather(parts=parts)
            data = pather.tail(serder=serder)
            cigars = hab.sign(ser=data,
                              verfers=hab.kever.verfers,
                              indexed=False)
            sadcigars.append((pather, cigars))

    return sadsigers, sadcigars


def transSeal(hab):
    """Return seal components and signing indices for the current Habitat state.

    Derives the prefixer, seqner, and diger from the Habitat's current
    establishment event (``kever.lastEst``). For a group Habitat the signing
    index is the position of the member Habitat's prefix within the group's
    signing member list (smids); for a non-group Habitat the index is left as
    ``None`` so the default key order is used.

    Args:
        hab (Habitat): Signing environment whose current key-event state
            provides the seal and index information.

    Returns:
        tuple: A four-element tuple ``(prefixer, seqner, diger, indices)``
        where:

        - **prefixer** (*Prefixer*) — Identifier prefix of the establishment
          event used for signing.
        - **seqner** (*Seqner*) — Sequence number of that establishment event.
        - **diger** (*Diger*) — SAID of that establishment event.
        - **indices** (*list[int] | None*) — ``[index]`` giving the signer's
          position in the group's smids list, or ``None`` for non-group
          Habitats (uses default key order).
    """
    if not isinstance(hab, GroupHab):  # not a group use own kever
        indices = None  # use default order
    else:  # group so use gid kever
        smids, _ = hab.members()
        indices = [smids.index(hab.mhab.pre)]  # use group order*

    kever = hab.kever
    prefixer = kever.prefixer
    seqner = Seqner(sn=kever.lastEst.s)
    diger = Diger(qb64=kever.lastEst.d)

    return prefixer, seqner, diger, indices


#class SadPathSigGroup:
    #""" Transposable group of signatures

    #Supports transposing groups of signatures from transferable or non-transferable
    #identifiers

    #"""

    #def __init__(self, pather, cigars=None, sigers=None, tsgs=None):
        #self.pather = pather
        #self.cigars = cigars if cigars is not None else []
        #self.sigers = sigers if sigers is not None else []
        #self.tsgs = tsgs if tsgs is not None else []

    #def transpose(self, pather):
        #""" Transpose path for all signatures in group

        #Parameters:
            #pather:

        #"""
        #self.pather = self.pather.root(pather)

    #@property
    #def proof(self):
        ## Transpose the signaturees to point to the new location
        #sadsigers = []
        #if len(self.sigers) > 0:  # iterate over each tsg
            #sadsigers.append((self.pather, self.sigers))

        #sadtsgs = []
        #for prefixer, seqner, diger, sigers in self.tsgs:  # iterate over each tsg
            #sadtsgs.append((self.pather, prefixer, seqner, diger, sigers))

        #sadcigars = []
        #for cigar in self.cigars:
            #sadcigars.append((self.pather, cigar))

        #return eventing.proofize(sadsigers=sadsigers, sadcigars=sadcigars, sadtsgs=sadtsgs)
