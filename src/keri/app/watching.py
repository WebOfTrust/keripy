# -*- encoding: utf-8 -*-
"""
KERI
keri.app.watching module

"""
from collections import namedtuple

Stateage = namedtuple("Stateage", 'even ahead behind duplicitous')

States = Stateage(even="even", ahead="ahead", behind="behind", duplicitous="duplicitous")


class WitnessState:
    wit: str
    state: Stateage
    sn: int
    dig: str


def diffState(wit, preksn, witksn):
    witstate = WitnessState()
    witstate.wit = wit
    mysn = int(preksn.s, 16)
    mydig = preksn.d
    witstate.sn = int(witksn.f, 16)
    witstate.dig = witksn.d

    # At the same sequence number, check the DIGs
    if mysn == witstate.sn:
        if mydig == witstate.dig:
            witstate.state = States.even
        else:
            witstate.state = States.duplicitous

    # This witness is behind and will need to be caught up.
    elif mysn > witstate.sn:
        witstate.state = States.behind

    # mysn < witstate.sn - We are behind this witness (multisig or restore situation).
    # Must ensure that controller approves this event or a recovery rotation is needed
    else:
        witstate.state = States.ahead

    return witstate
