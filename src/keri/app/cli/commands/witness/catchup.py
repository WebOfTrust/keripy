# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse
import json

from keri import help
from hio.base import doing

from hio.core import http

from keri import kering
from keri.app import habbing, httping
from keri.app.cli.common import existing

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

    doer = CatchupDoer(name=name, base=base, alias=alias, bran=bran, witness=witness, force=force)

    return [doer]


class CatchupDoer(doing.DoDoer):
    """ DoDoer for sending full KEL to a witness to catch it up.
    """

    def __init__(self, name, base, alias, bran, witness, force=False):

        hby = existing.setupHby(name=name, base=base, bran=bran)
        self.hbyDoer = habbing.HaberyDoer(habery=hby)  # setup doer
        self.alias = alias
        self.hby = hby
        self.witness = witness
        self.force = force

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

        # Collect and display all events that will be sent
        events = list(hab.db.clonePreIter(pre=hab.pre))
        print(f"\nEvents to send to witness {self.witness}:")
        print("=" * 70)

        for i, fmsg in enumerate(events):
            msg = bytes(fmsg)
            # Parse out the JSON message body
            try:
                # Find start and end of JSON
                json_start = msg.find(b'{')
                if json_start >= 0:
                    # Parse to find the full JSON
                    depth = 0
                    json_end = json_start
                    in_string = False
                    escape = False
                    for j in range(json_start, len(msg)):
                        ch = chr(msg[j])
                        if escape:
                            escape = False
                        elif ch == '\\' and in_string:
                            escape = True
                        elif ch == '"' and not escape:
                            in_string = not in_string
                        elif not in_string:
                            if ch == '{':
                                depth += 1
                            elif ch == '}':
                                depth -= 1
                                if depth == 0:
                                    json_end = j + 1
                                    break

                    json_body = msg[json_start:json_end].decode('utf-8')
                    ked = json.loads(json_body)
                    attachments = msg[json_end:].decode('utf-8')

                    print(f"\nEvent {i + 1}/{len(events)}:")
                    print(f"  Type: {ked.get('t', 'unknown')}")
                    print(f"  SN: {ked.get('s', 'unknown')}")
                    print(f"  SAID: {ked.get('d', 'unknown')}")
                    print(f"  Body: {json.dumps(ked, indent=4)}")
                    if attachments:
                        print(f"  Attachments: {attachments}")
                    print("-" * 70)
                else:
                    print(f"\nEvent {i + 1}/{len(events)}: (raw)")
                    print(f"  {msg.decode('utf-8', errors='replace')}")
                    print("-" * 70)
            except Exception:
                print(f"\nEvent {i + 1}/{len(events)}: (raw)")
                print(f"  {msg.decode('utf-8', errors='replace')}")
                print("-" * 70)

        print(f"\nTotal events: {len(events)}")
        print("=" * 70)

        # Prompt user to continue
        try:
            input("\nPress Enter to send events to witness...")
        except EOFError:
            pass  # Handle non-interactive mode

        print(f"\nSending full KEL to witness {self.witness}...")

        # Get witness URL and create HTTP client
        urls = hab.fetchUrls(eid=self.witness, scheme=kering.Schemes.http) or \
               hab.fetchUrls(eid=self.witness, scheme=kering.Schemes.https)
        if not urls:
            print(f"Error: unable to find HTTP endpoint for witness {self.witness}")
            self.remove([self.hbyDoer])
            return

        from urllib.parse import urlparse
        url = urls[kering.Schemes.http] if kering.Schemes.http in urls else urls[kering.Schemes.https]
        print(f"Witness URL: {url}")
        up = urlparse(url)
        client = http.clienting.Client(scheme=up.scheme, hostname=up.hostname, port=up.port)
        clientDoer = http.clienting.ClientDoer(client=client)
        self.extend([clientDoer])

        # Send each event and log response
        success_count = 0
        error_count = 0

        for i, fmsg in enumerate(events):
            print(f"\nSending event {i + 1}/{len(events)}...")
            httping.streamCESRRequests(client=client, dest=self.witness, ims=bytearray(fmsg))

            # Wait for response
            while not client.responses:
                yield self.tock

            # Get and log response
            rep = client.responses.popleft()
            status = rep.status
            reason = rep.reason
            body = rep.body.decode('utf-8') if rep.body else ""

            if 200 <= status < 300:
                print(f"  Response: {status} {reason}")
                success_count += 1
            else:
                print(f"  ERROR Response: {status} {reason}")
                if body:
                    print(f"  Response body: {body}")
                error_count += 1

        print(f"\n{'=' * 70}")
        print(f"Summary: {success_count} successful, {error_count} errors")
        if error_count == 0:
            print(f"KEL sent successfully. Witness should now be at sn={hab.kever.sn}")
        else:
            print(f"WARNING: {error_count} events failed to send!")
        print(f"{'=' * 70}")

        self.remove([clientDoer, self.hbyDoer])

        return
