# -*- encoding: utf-8 -*-
"""
keri.kli.common.displaying module

"""

from keri.db import dbing


def printGroups(hab):
    """
    Print identifier and participant information for an environment (Habitat)
    Uses the .gids database to determine groups

    Parameters:
        hab (Habitat): environment for whom to print groups

    """
    groups = hab.db.gids.getItemIter()
    for (aid,), group in groups:
        printGroup(hab, aid, group)


def printGroup(hab, aid, group):
    """
    Print identifier and participant information for a specific group

    Parameters:
        hab (Habitat): environment for whom to print groups
        aid (str): qb64 of the identifier prefix of the group
        group (GroupIdentifier): the local identifier and list of participants

    """
    printIdentifier(hab, aid)

    aids = group.aids
    parts = "Participants: \n" + ("\t{}\n" * len(aids))
    print(parts.format(*aids))
    print()


def printIdentifier(hab, pre):
    """
    Print current state information for the identifier prefix pre

    Parameters:
        hab (Habitat): environment that contains the information for the idenfitier prefix
        pre (str): qb64 of the identifier prefix
    :return:
    """
    kever = hab.kevers[pre]
    ser = kever.serder
    dgkey = dbing.dgKey(ser.preb, ser.digb)
    wigs = hab.db.getWigs(dgkey)

    print("Prefix:\t{}".format(hab.pre))
    print("Seq No:\t{}".format(kever.sn))
    print("\nWitnesses:")
    print("Count:\t\t{}".format(len(kever.wits)))
    print("Receipts:\t{}".format(len(wigs)))
    print("Threshold:\t{}".format(kever.toad))
    print("\nPublic Keys:\t")
    for idx, verfer in enumerate(kever.verfers):
        print(f'\t{idx+1}. {verfer.qb64}')
    print()
