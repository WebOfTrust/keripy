# -*- encoding: utf-8 -*-
"""
KERI
keri.app.signing module

"""
from ..kering import Vrsn_1_0, Vrsn_2_0
from ..app.habbing import GroupHab
from .. import core
from ..core import coring, eventing, counting



def serialize(creder, prefixer, seqner, saider):
    craw = bytearray(creder.raw)
    craw.extend(core.Counter(core.Codens.SealSourceTriples, count=1,
                             gvrsn=Vrsn_1_0).qb64b)
    craw.extend(prefixer.qb64b)
    craw.extend(seqner.qb64b)
    craw.extend(saider.qb64b)

    return bytes(craw)


def ratify(hab, serder, paths=None, pipelined=False):
    """ Sign the SAD or SAIDs with the keys from the Habitat.

    Sign the SADs or SAIDs of the SADs as identified by the paths.  If paths is
    None, default to signing the root SAD only.

    Parameters:
        hab (Habitat): environment used to sign the SAD
        serder (Union[Serder,Creder]): the self addressing data (SAD)
        paths (list): list of paths specified as arrays of path components
        pipelined (bool): True means prepend pipelining count code to attachemnts
            False means to not prepend pipelining count code

    Returns:
        bytes: serialized SAD with qb64 CESR Proof Signature attachments

    """
    paths = [[]] if paths is None else paths
    sadsigers, sadcigars = signPaths(hab=hab, serder=serder, paths=paths)
    return provision(serder, sadsigers=sadsigers, sadcigars=sadcigars, pipelined=pipelined)


def provision(serder, *, sadsigers=None, sadcigars=None, pipelined=False):
    """
    Attaches indexed signatures from sigers and/or cigars and/or wigers to
    KERI message data from serder
    Parameters:
        serder (Union[Serder,Creder]): instance containing the event
        sadsigers (list): of Siger instances (optional) to create indexed signatures
        sadcigars (list): optional list of Cigars instances of non-transferable non indexed
            signatures from  which to form receipt couples.
            Each cigar.vefer.qb64 is pre of receiptor and cigar.qb64 is signature
        pipelined (bool): True means prepend pipelining count code to attachemnts
            False means to not prepend pipelining count code

    Returns: bytearray SAD with CESR Proof Signature

    """
    msg = bytearray(serder.raw)  # make copy into new bytearray so can be deleted
    if not (sadsigers or sadcigars):
        raise ValueError("Missing attached signatures on message = {}."
                         "".format(serder.ked))

    msg.extend(eventing.proofize(sadtsgs=sadsigers, sadcigars=sadcigars, pipelined=pipelined))
    return msg


def signPaths(hab, serder, paths):
    """ Sign the SAD or SAIDs with the keys from the Habitat.

    Sign the SADs or SAIDs of the SADs as identified by the paths.

    Parameters:
        hab (Habitat): environment used to sign the SAD
        serder (Union[Serder,Creder]): the self addressing data (SAD)
        paths (list): list of paths specified as arrays of path components

    Returns:
        str: qb64 signature attachment

    """

    sadsigers = []
    sadcigars = []

    if hab.kever.prefixer.transferable:
        prefixer, seqner, saider, indices = transSeal(hab)
        for path in paths:
            pather = coring.Pather(path=path)
            data = pather.tail(serder=serder)

            sigers = hab.sign(ser=data,
                              verfers=hab.kever.verfers,
                              indexed=True)
            sadsigers.append((pather, prefixer, seqner, saider, sigers))

    else:
        for path in paths:
            pather = coring.Pather(path=path)
            data = pather.tail(serder=serder)
            cigars = hab.sign(ser=data,
                              verfers=hab.kever.verfers,
                              indexed=False)
            sadcigars.append((pather, cigars))

    return sadsigers, sadcigars


def transSeal(hab):
    """ Returns seal components and signing indices as appropriate for current state of Habitat

    Args:
        hab (Habitat): environment that contains the information for the idenfitier prefix

    Returns:
       tuple:  seal components with signing indices

    ToDo: NRR
       indices for both hab.smids and hab.rmids
    """
    # create SealEvent or SealLast for endorser's est evt whose keys are
    # used to sign
    if not isinstance(hab, GroupHab):  # not a group use own kever
        indices = None  # use default order
    else:  # group so use gid kever
        smids, _ = hab.members()
        indices = [smids.index(hab.mhab.pre)]  # use group order*

    kever = hab.kever
    prefixer = kever.prefixer
    seqner = coring.Seqner(sn=kever.lastEst.s)
    saider = coring.Saider(qb64=kever.lastEst.d)

    return prefixer, seqner, saider, indices


class SadPathSigGroup:
    """ Transposable group of signatures

    Supports transposing groups of signatures from transferable or non-transferable
    identifiers

    """

    def __init__(self, pather, cigars=None, sigers=None, tsgs=None):
        self.pather = pather
        self.cigars = cigars if cigars is not None else []
        self.sigers = sigers if sigers is not None else []
        self.tsgs = tsgs if tsgs is not None else []

    def transpose(self, pather):
        """ Transpose path for all signatures in group

        Parameters:
            pather:

        """
        self.pather = self.pather.root(pather)

    @property
    def proof(self):
        # Transpose the signaturees to point to the new location
        sadsigers = []
        if len(self.sigers) > 0:  # iterate over each tsg
            sadsigers.append((self.pather, self.sigers))

        sadtsgs = []
        for prefixer, seqner, diger, sigers in self.tsgs:  # iterate over each tsg
            sadtsgs.append((self.pather, prefixer, seqner, diger, sigers))

        sadcigars = []
        for cigar in self.cigars:
            sadcigars.append((self.pather, cigar))

        return eventing.proofize(sadsigers=sadsigers, sadcigars=sadcigars, sadtsgs=sadtsgs)





