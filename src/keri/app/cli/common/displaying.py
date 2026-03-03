# -*- encoding: utf-8 -*-
"""
keri.app.cli.common.displaying module

"""
import sys

from ..common import terming
from ...habbing import GroupHab
from ....db import dbing


def printIdentifier(hby, pre, label="Identifier"):
    """
    Print current state information for the identifier prefix pre

    Parameters:
        hab (Habitat): environment that contains the information for the idenfitier prefix
        pre (str): qb64 of the identifier prefix
    :return:
    """

    hab = hby.habs[pre]
    if hab.accepted:
        kever = hab.kever
        ser = kever.serder
        wigers = hab.db.wigs.get(keys=(ser.preb, kever.lastEst.d))
        seal = hab.db.aess.get(keys=(ser.preb, kever.lastEst.d))

        print(f"Alias: \t{hab.name}")
        print("{}: {}".format(label, pre))
        print("Seq No:\t{}".format(kever.sner.num))
        if kever.delegated:
            print("Delegated Identifier")
            sys.stdout.write(f"    Delegator:  {kever.delpre} ")
            if seal:
                print(f"{terming.Colors.OKGREEN}{terming.Symbols.CHECKMARK} Anchored{terming.Colors.ENDC}")
            else:
                print(f"{terming.Colors.FAIL}{terming.Symbols.FAILED} Not Anchored{terming.Colors.ENDC}")
            print()

        if isinstance(hab, GroupHab):
            print("Group Identifier")
            sys.stdout.write(f"    Local Indentifier:  {hab.mhab.pre} ")
            if hab.accepted:
                print(f"{terming.Colors.OKGREEN}{terming.Symbols.CHECKMARK} Fully Signed{terming.Colors.ENDC}")
            else:
                print(f"{terming.Colors.FAIL}{terming.Symbols.FAILED} Not Fully Signed{terming.Colors.ENDC}")

        print("\nWitnesses:")
        print("Count:\t\t{}".format(len(kever.wits)))
        print("Receipts:\t{}".format(len(wigers)))
        print("Threshold:\t{}".format(kever.toader.num))
        print("\nPublic Keys:\t")
        for idx, verfer in enumerate(kever.verfers):
            print(f'\t{idx+1}. {verfer.qb64}')
        print()
    else:
        print("{}: {}".format(label, hab.pre))
        print("Seq No:\t{}".format(0))

        if isinstance(hab, GroupHab):
            print("Group Identifier")
            sys.stdout.write(f"    Local Indentifier:  {hab.mhab.pre} ")
            if hab.accepted:
                print(f"{terming.Colors.OKGREEN}{terming.Symbols.CHECKMARK} Anchored{terming.Colors.ENDC}")
            else:
                print(f"{terming.Colors.FAIL}{terming.Symbols.FAILED} Not Anchored{terming.Colors.ENDC}")

        print()


def printExternal(hby, pre, label="Identifier"):
    """
    Print current state information for the identifier prefix pre

    Parameters:
        hab (Habitat): environment that contains the information for the idenfitier prefix
        pre (str): qb64 of the identifier prefix
    :return:
    """

    kever = hby.kevers[pre]
    ser = kever.serder
    wigers = hby.db.wigs.get(keys=(ser.preb, kever.lastEst.d))
    anchor = hby.db.aess.get(keys=(ser.preb, kever.lastEst.d))

    print("{}: {}".format(label, pre))
    print("Seq No:\t{}".format(kever.sner.num))
    if kever.delegated:
        print("Delegated Identifier")
        sys.stdout.write(f"    Delegator:  {kever.delpre} ")
        if anchor:
            print(f"{terming.Colors.OKGREEN}{terming.Symbols.CHECKMARK} Anchored{terming.Colors.ENDC}")
        else:
            print(f"{terming.Colors.FAIL}{terming.Symbols.FAILED} Not Anchored{terming.Colors.ENDC}")
        print()


    print("\nWitnesses:")
    print("Count:\t\t{}".format(len(kever.wits)))
    print("Receipts:\t{}".format(len(wigers)))
    print("Threshold:\t{}".format(kever.toader.num))
    print("\nPublic Keys:\t")
    for idx, verfer in enumerate(kever.verfers):
        print(f'\t{idx+1}. {verfer.qb64}')
    print()

