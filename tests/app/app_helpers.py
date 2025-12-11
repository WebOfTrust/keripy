import json
from contextlib import contextmanager
from typing import List, Generator, Tuple, Any

from hio.base import Doer, Doist

from keri.app import habbing, delegating
from keri.app.agenting import WitnessReceiptor, Receiptor
from keri.app.configing import Configer
from keri.app.delegating import Anchorer
from keri.app.forwarding import Poster
from keri.app.habbing import openHab, HaberyDoer, Habery, Hab, openHby
from keri.app.indirecting import MailboxDirector, setupWitness
from keri.app.notifying import Notifier
from keri.core import Salter
from keri.peer.exchanging import Exchanger


@contextmanager
def openWit(name: str = 'wan', tcpPort: int = 6632, httpPort: int = 6642, salt: bytes = b'abcdefg0123456789') -> Generator[Tuple[Habery, Hab, List[Doer], str], None, None]:
    """
    Context manager for a KERI witness along with the Doers needed to run it.
    Expects the Doers to be run by the caller.

    Returns a tuple of (Habery, Hab, witness Doers, witness controller OOBI URL)
    """
    salt = Salter(raw=salt).qb64
    # Witness config
    witCfg = f"""{{
          "dt": "2025-12-11T11:02:30.302010-07:00",
          "{name}": {{
            "dt": "2025-12-11T11:02:30.302010-07:00",
            "curls": ["tcp://127.0.0.1:{tcpPort}/", "http://127.0.0.1:{httpPort}/"]}}}}"""
    cf = Configer(name=name, temp=False, reopen=True, clear=False)
    cf.put(json.loads(witCfg))
    with (
            openHab(salt=bytes(salt, 'utf-8'), name=name, transferable=False, temp=True, cf=cf) as (hby, hab)
    ):
        oobi = f'http://127.0.0.1:{httpPort}/oobi/{hab.pre}/controller?name={name}&tag=witness'
        hbyDoer = HaberyDoer(habery=hby)
        doers: List[Doer] = [hbyDoer]
        doers.extend(setupWitness(alias=name, hby=hby, tcpPort=tcpPort, httpPort=httpPort))
        yield hby, hab, doers, oobi


@contextmanager
def openCtrlWited(witOobi: str, name: str = 'aceCtlrKS', salt: bytes = b'aaaaaaa0123456789') -> Generator[Tuple[Habery, List[Doer]], None, None]:
    """
    Context manager for setting up a KERI controller that uses a witness as its mailbox and witness.
    Sets up the Doers needed to run a controller including both single sig and multi-sig handlers.
    Relies on an outer context manager or caller to perform OOBI resolution and inception of the controller AID.
    Receives a witness OOBI URL to use as its configured witness.

    Expects the Doers to be run by the caller.

    Returns a tuple of (Habery, controller Doers)
    """
    ctlrCfg = f"""{{
            "dt": "2025-12-11T11:02:30.302010-07:00",
            "iurls": [\"{witOobi}\"]}}"""
    cf = Configer(name=name, temp=False, reopen=True, clear=False)
    cf.put(json.loads(ctlrCfg))
    with openHby(salt=salt, name=name, temp=True, cf=cf) as hby:
        hbyDoer = habbing.HaberyDoer(habery=hby)
        anchorer = Anchorer(hby=hby, proxy=None)
        postman = Poster(hby=hby)
        exc = Exchanger(hby=hby, handlers=[])
        notifier = Notifier(hby=hby)
        delegating.loadHandlers(hby=hby, exc=exc, notifier=notifier)
        mbx = MailboxDirector(hby=hby, exc=exc, topics=['/receipt', '/replay', '/reply', '/delegate', '/multisig'])
        witReceiptor = WitnessReceiptor(hby=hby)
        receiptor = Receiptor(hby=hby)
        doers = [hbyDoer, anchorer, postman, mbx, witReceiptor, receiptor]
        yield hby, doers

@contextmanager
def openCtrlWitIcpd(
        doist: Doist, witOobi: str, witDoers: List[Doer],
        name: str = 'aceCtlrKS',
        salt: bytes = b'aaaaaaa0123456789',
        alias='aceCtlrAIC'):
    """
    Uses the Doist to perform both OOBI resolution of the witness and inception of the controller AID.
    """
    pass