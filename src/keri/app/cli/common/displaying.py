# -*- encoding: utf-8 -*-
"""
keri.kli.common.displaying module

"""
import sys

from keri.app.cli.common import terming
from keri.app.habbing import GroupHab
from keri.db import dbing


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
        dgkey = dbing.dgKey(ser.preb, ser.saidb)
        wigs = hab.db.getWigs(dgkey)
        dgkey = dbing.dgKey(ser.preb, kever.lastEst.d)
        seal = hab.db.getAes(dgkey)

        print(f"Alias: \t{hab.name}")
        print("{}: {}".format(label, pre))
        print("Seq No:\t{}".format(kever.sner.num))
        if kever.delegated:
            print("Delegated Identifier")
            sys.stdout.write(f"    Delegator:  {kever.delegator} ")
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
        print("Receipts:\t{}".format(len(wigs)))
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
    dgkey = dbing.dgKey(ser.preb, ser.saidb)
    wigs = hby.db.getWigs(dgkey)
    dgkey = dbing.dgKey(ser.preb, kever.lastEst.d)
    anchor = hby.db.getAes(dgkey)

    print("{}: {}".format(label, pre))
    print("Seq No:\t{}".format(kever.sner.num))
    if kever.delegated:
        print("Delegated Identifier")
        sys.stdout.write(f"    Delegator:  {kever.delegator} ")
        if anchor:
            print(f"{terming.Colors.OKGREEN}{terming.Symbols.CHECKMARK} Anchored{terming.Colors.ENDC}")
        else:
            print(f"{terming.Colors.FAIL}{terming.Symbols.FAILED} Not Anchored{terming.Colors.ENDC}")
        print()


    print("\nWitnesses:")
    print("Count:\t\t{}".format(len(kever.wits)))
    print("Receipts:\t{}".format(len(wigs)))
    print("Threshold:\t{}".format(kever.toader.num))
    print("\nPublic Keys:\t")
    for idx, verfer in enumerate(kever.verfers):
        print(f'\t{idx+1}. {verfer.qb64}')
    print()

