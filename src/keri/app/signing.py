# -*- encoding: utf-8 -*-
"""
KERI
keri.app.signing module

"""
from keri.core import coring, eventing



def ratify(hab, serder, paths=None, pipelined=False):
    """ Sign the SAD or SAIDs with the keys from the Habitat.

    Sign the SADs or SAIDs of the SADs as identified by the paths.  If paths is
    None, default to signing the root SAD only.

    Parameters:
        hab (Habitat): environment used to sign the SAD
        serder (Union[Serder,Credentialer]): the self addressing data (SAD)
        paths (list): list of paths specified as arrays of path components
        pipelined (bool): True means prepend pipelining count code to attachemnts
            False means to not prepend pipelining count code

    Returns:
        str: serialized SAD with qb64 CESR Proof Signature attachments

    """
    paths = [[]] if paths is None else paths
    sadsigers, sadcigars = signPaths(hab=hab, serder=serder, paths=paths)
    return provision(serder, sadsigers=sadsigers, sadcigars=sadcigars, pipelined=pipelined)


def provision(serder, *, sadsigers=None, sadcigars=None, pipelined=False):
    """
    Attaches indexed signatures from sigers and/or cigars and/or wigers to
    KERI message data from serder
    Parameters:
        serder (Union[Serder,Credentialer]): instance containing the event
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

    msg.extend(eventing.proofize(sadsigers=sadsigers, sadcigars=sadcigars, pipelined=pipelined))
    return msg


def signPaths(hab, serder, paths):
    """ Sign the SAD or SAIDs with the keys from the Habitat.

    Sign the SADs or SAIDs of the SADs as identified by the paths.

    Parameters:
        hab (Habitat): environment used to sign the SAD
        serder (Union[Serder,Credentialer]): the self addressing data (SAD)
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
            data = pather.rawify(serder=serder)

            sigers = hab.mgr.sign(ser=data,
                                  verfers=hab.kever.verfers,
                                  indexed=True,
                                  indices=indices)
            sadsigers.append((pather, prefixer, seqner, saider, sigers))

    else:
        for path in paths:
            pather = coring.Pather(path=path)
            data = pather.rawify(serder=serder)
            cigars = hab.mgr.sign(ser=data,
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
    """
    # create SealEvent or SealLast for endorser's est evt whose keys are
    # used to sign
    group = hab.db.gids.get(hab.pre)  # is it a group ID
    if group is None:  # not a group use own kever
        kever = hab.kever
        indices = None  # use default order
    else:  # group so use gid kever
        kever = hab.kevers[group.gid]
        indices = [group.aids.index(hab.pre)]  # use group order*

    prefixer = kever.prefixer
    seqner = coring.Seqner(sn=kever.lastEst.s)
    saider = coring.Saider(qb64=kever.lastEst.d)

    return prefixer, seqner, saider, indices
