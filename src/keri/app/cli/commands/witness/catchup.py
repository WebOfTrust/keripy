# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse

from keri import help
from hio.base import doing

from keri.app import habbing, agenting, httping
from keri.app.cli.common import existing
from keri.core import serdering

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Send full KEL to a specific witness to catch it up')
parser.set_defaults(handler=lambda args: handler(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--alias', '-a', help='human readable alias for the identifier prefix', required=True)

# Authentication for keystore
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran
parser.add_argument('--witness', '-w', help='witness AID to send KEL to', required=True)
parser.add_argument('--force', '-f', help='send KEL even if witness is not in current witness pool',
                    action='store_true', default=False)
parser.add_argument('--verbose', '-V', help='show detailed progress for each event',
                    action='store_true', default=False)


def handler(args):
    """
    Send full KEL to a specific witness to catch it up.

    Args:
        args(Namespace): arguments object from command line
    """

    name = args.name
    base = args.base
    bran = args.bran
    alias = args.alias
    witness = args.witness
    force = args.force
    verbose = args.verbose

    doer = CatchupDoer(name=name, base=base, alias=alias, bran=bran, witness=witness, force=force, verbose=verbose)

    return [doer]


class CatchupDoer(doing.DoDoer):
    """ DoDoer for sending full KEL to a witness to catch it up.
    """

    def __init__(self, name, base, alias, bran, witness, force=False, verbose=False):

        hby = existing.setupHby(name=name, base=base, bran=bran)
        self.hbyDoer = habbing.HaberyDoer(habery=hby)  # setup doer
        self.alias = alias
        self.hby = hby
        self.witness = witness
        self.force = force
        self.verbose = verbose

        doers = [self.hbyDoer, doing.doify(self.catchupDo)]

        super(CatchupDoer, self).__init__(doers=doers)

    def catchupDo(self, tymth, tock=0.0):
        """
        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value

        Returns:  doifiable Doist compatible generator method
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        hab = self.hby.habByName(name=self.alias)
        if hab is None:
            print(f"Error: unknown alias {self.alias}")
            self.remove([self.hbyDoer])
            return

        # Validate witness is in the current witness list
        if self.witness not in hab.kever.wits:
            if not self.force:
                print(f"Error: {self.witness} is not a witness for {self.alias}")
                print(f"Current witnesses: {hab.kever.wits}")
                print("Use --force to send KEL anyway")
                self.remove([self.hbyDoer])
                return
            else:
                print(f"Warning: {self.witness} is not a witness for {self.alias}, forcing anyway")

        if self.verbose:
            # Use verbose catchup with progress reporting
            yield from self.verboseCatchup(hab)
        else:
            receiptor = agenting.Receiptor(hby=self.hby)
            self.extend([receiptor])
            print(f"Sending full KEL to witness {self.witness}...")
            yield from receiptor.catchup(hab.pre, self.witness)
            self.remove([receiptor])

        print(f"KEL sent successfully. Witness should now be at sn={hab.kever.sn}")

        self.remove([self.hbyDoer])

        return

    def verboseCatchup(self, hab):
        """Verbose catchup with progress reporting for each event."""
        from keri.app.agenting import httpClient

        client, clientDoer = httpClient(hab, self.witness)
        self.extend([clientDoer])

        print(f"Sending full KEL to witness {self.witness}...")
        print(f"Controller KEL has {hab.kever.sn + 1} events (sn 0 to {hab.kever.sn})")
        print()

        event_count = 0
        success_count = 0
        error_count = 0

        for fmsg in hab.db.clonePreIter(pre=hab.pre):
            # Parse to get event info
            try:
                serder = serdering.SerderKERI(raw=fmsg)
                sn = serder.sn
                ilk = serder.ilk
            except Exception:
                sn = '?'
                ilk = '?'

            event_count += 1
            print(f"  Sending event sn={sn} ilk={ilk}...", end=" ", flush=True)

            httping.streamCESRRequests(client=client, dest=self.witness, ims=bytearray(fmsg))
            while not client.responses:
                yield self.tock

            # Check response
            response = client.responses.popleft()
            status = response.get('status', 'unknown')

            if status in (200, 204):
                print(f"OK (HTTP {status})")
                success_count += 1
            else:
                print(f"ERROR (HTTP {status})")
                error_count += 1
                body = response.get('body', b'')
                if body:
                    print(f"    Response: {body[:200]}")

        print()
        print(f"Summary: {event_count} events sent, {success_count} succeeded, {error_count} errors")

        self.remove([clientDoer])
