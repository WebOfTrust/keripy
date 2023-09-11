# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import string

import os

import argparse
import datetime
import sys
from inspect import isgeneratorfunction

from hio import help
from hio.base import doing
from prettytable import PrettyTable
from prompt_toolkit.key_binding import KeyBindings

from keri import kering
from keri.app import indirecting, notifying, connecting
from keri.app.cli.common import existing, terming
from keri.core import scheming, parsing
from keri.help import helping
from keri.peer import exchanging
from keri.vc import protocoling, proving
from keri.vdr import credentialing, verifying
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import NestedCompleter
from prompt_toolkit.formatted_text import FormattedText
from prompt_toolkit.history import FileHistory

logger = help.ogler.getLogger()

parser = argparse.ArgumentParser(description='Accept any newly issued credentials')
parser.set_defaults(handler=lambda args: accept(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--alias', '-a', help='human readable alias for the identifier to whom the credential was issued',
                    default=None)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran

parser.add_argument("--verbose", "-V", help="print full JSON of all credentials", action="store_true")
parser.add_argument("--said", "-s", help="display only the SAID of found credentials, one per line.",
                    action="store_true")
parser.add_argument("--auto", "-Y", help="auto accept any issued credentials non-interactively", action="store_true")
parser.add_argument("--poll", "-P", help="Poll mailboxes for any issued credentials", action="store_true")


def accept(args):
    """ Command line list credential registries handler

    """
    ld = AcceptDoer(name=args.name,
                    alias=args.alias,
                    base=args.base,
                    bran=args.bran,
                    poll=args.poll,
                    verbose=args.verbose,
                    auto=args.auto,
                    said=args.said)
    return [ld]


class AcceptDoer(doing.DoDoer):

    def __init__(self, name, alias, base, bran, poll=False, verbose=False, auto=False, said=False):
        self.poll = poll
        self.verbose = verbose
        self.auto = auto
        self.said = said

        self.hby = existing.setupHby(name=name, base=base, bran=bran)
        if alias is None:
            alias = existing.aliasInput(self.hby)

        self.hab = self.hby.habByName(alias)
        self.notifier = notifying.Notifier(hby=self.hby)
        self.rgy = credentialing.Regery(hby=self.hby, name=name, base=base)
        self.vry = verifying.Verifier(hby=self.hby, reger=self.rgy.reger)
        self.exc = exchanging.Exchanger(hby=self.hby, handlers=[])
        protocoling.loadHandlers(self.hby, self.exc, self.rgy, self.notifier)
        self.mbx = indirecting.MailboxDirector(hby=self.hby, topics=['/replay', 'reply', '/credential'],
                                               exc=self.exc, verifier=self.vry)

        self.prompt = InboxPrompt(self.hby, self.rgy, self.notifier, self.mbx)
        self.doers = [self.mbx, self.prompt]

        super(AcceptDoer, self).__init__(doers=self.doers + [doing.doify(self.acceptDo)])

    def acceptDo(self, tymth, tock=0.0):
        """ Check for any credential messages in mailboxes and list all held credentials

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value

        Returns:  doifiable Doist compatible generator method

        """
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while not self.prompt.done:
            yield self.tock

        self.remove(self.doers)

    def foo(self, route, attrs, keys):
        if route == '/credential/issue':
            print("Credential issuance received:")
            said = attrs['d']
            exn, pathed = exchanging.cloneMessage(self.hby, said)
            sad = exn.ked['e']["acdc"]
            iss = exn.ked['e']['iss']

            schema = sad['s']
            scraw = self.mbx.verifier.resolver.resolve(schema)
            if not scraw:
                raise kering.ConfigurationError("Credential schema {} not found".format(schema))

            schemer = scheming.Schemer(raw=scraw)
            creder = self.rgy.reger.creds.get(keys=(sad['d'],))
            if creder is None:
                accepted = f"No {terming.Colors.FAIL}{terming.Symbols.FAILED}{terming.Colors.ENDC}"
            else:
                accepted = f"Yes {terming.Colors.OKGREEN}{terming.Symbols.CHECKMARK}{terming.Colors.ENDC}"
            print(f"Credential {sad['d']}:")
            print(f"    Type: {schemer.sed['title']}")
            print(
                f"    Status: Issued {terming.Colors.OKGREEN}{terming.Symbols.CHECKMARK}{terming.Colors.ENDC}")
            print(f"    Issued by {sad['i']}")
            print(f"    Issued on {iss['dt']}")
            print(f"    Already accepted? {accepted}")

            if creder is not None:
                self.deleteNote(keys=keys)
                return

            creder = proving.Creder(ked=sad)

            if self.auto:
                print("Auto accepting credential...")
                yes = True
            else:
                yn = input(f"\nAccept [Y|n]? ")
                yes = yn in ('', 'y', 'Y')

            if yes:
                ims = bytearray(creder.raw) + pathed["acdc"]
                parsing.Parser(vry=self.vry).parse(ims=ims)

                while not self.rgy.reger.creds.get(keys=creder.saidb):
                    yield self.tock

                print(f"{creder.said} Accepted {terming.Colors.OKGREEN}{terming.Symbols.CHECKMARK}"
                      f"{terming.Colors.ENDC}")

            self.deleteNote(keys=keys)


HISTORY_FILE = os.path.expanduser('~/.keri_history')
IDENTCHARS = string.ascii_letters + string.digits + '_'


class InboxPrompt(doing.Doer):
    intro = 'Welcome to the KERI IPEX Protocol Inbox Shell.   Type help or ? to list commands.\n'

    def __init__(self, hby, rgy, notifier, mbx):
        self.hby = hby
        self.rgy = rgy
        self.notifier = notifier
        self.mbx = mbx
        self.org = connecting.Organizer(hby=self.hby)
        self.notes = []

        history = FileHistory(HISTORY_FILE)
        completer = NestedCompleter.from_nested_dict({"exit": None, "poll": None})
        self.session = PromptSession(completer=completer, complete_while_typing=False, history=history)

        super(InboxPrompt, self).__init__()

    def recur(self, tyme=None):
        print("\n", self.intro)
        while True:
            self.notes = []
            for keys, notice in self.notifier.noter.notes.getItemIter():
                if notice.pad['a']['r'].startswith("/exn/ipex"):
                    self.notes.append(notice)

            agentStatus = [
                ("bg:darkred bold", f'{len(self.notes)} Messages'),
            ]

            tb = FormattedText([
                ('bg:blue', ' IPEX Inbox:  '),
                *agentStatus,
            ])

            self.session.bottom_toolbar = tb

            text = self.session.prompt('(ipex) > ')

            if not text:
                continue

            cmd, arg, line = self.parseline(text)

            try:
                func = getattr(self, 'do_' + cmd)
            except AttributeError:
                self.default(line)
                continue

            if isgeneratorfunction(func):
                done = yield from func(arg)
            else:
                tyme = (yield 0.375)  # yields .tock then waits for next send
                done = func(arg)

            if done is True:
                break

        return True

    @staticmethod
    def default(line):
        """Called on an input line when the command prefix is not recognized.

        If this method is not overridden, it prints an error message and
        returns.

        """
        print('*** Unknown syntax: %s\n'%line)
        return False

    def parseline(self, line):
        """Parse the line into a command name and a string containing
        the arguments.  Returns a tuple containing (command, args, line).
        'command' and 'args' may be None if the line couldn't be parsed.
        """
        line = line.strip()
        if not line:
            return None, None, line
        elif line[0] == '?':
            line = 'help ' + line[1:]
        elif line[0] == '!':
            if hasattr(self, 'do_shell'):
                line = 'shell ' + line[1:]
            else:
                return None, None, line
        i, n = 0, len(line)
        while i < n and line[i] in IDENTCHARS:
            i = i+1
        cmd, arg = line[:i], line[i:].strip()
        return cmd, arg, line

    def do_poll(self, _):
        end = helping.nowUTC() + datetime.timedelta(seconds=5)
        sys.stdout.write(f"Checking mailboxes for any ipex messages")
        sys.stdout.flush()
        while helping.nowUTC() < end:
            sys.stdout.write(".")
            sys.stdout.flush()
            if "/credential" in self.mbx.times:
                end = self.mbx.times['/credential'] + datetime.timedelta(seconds=5)
            yield 1.0
        print("\n")

    @staticmethod
    def do_exit(_):
        """ Exit without saving """
        print("Closing")
        return True

    def deleteNote(self, keys):
        yn = input(f"\n Delete the notification [Y|n]?")
        if yn in ('', 'y', 'Y'):
            self.notifier.noter.notes.rem(keys=keys)

    def do_list(self, _):
        start = 0
        end = 9

        while True:
            tab = PrettyTable()
            fields = ["No.", "Type", "Source", "Message", "Sent"]
            tab.field_names = fields
            tab.align["Type"] = "l"

            buffer = self.notes[start:end]

            for idx, note in enumerate(buffer):
                attrs = note.attrs
                said = attrs['d']
                exn, pathed = exchanging.cloneMessage(self.hby, said)

                match exn.ked['r']:
                    case "/ipex/agree":
                        typ = "Agree"
                    case "/ipex/apply":
                        typ = "Apply"
                    case "/ipex/offer":
                        typ = "Offer"
                    case "/ipex/grant":
                        typ = "Grant"
                        show = self.show_grant
                    case "/ipex/spurn":
                        typ = "Spurn"
                    case _:
                        typ = "Unknown"
                senderAid = exn.ked['i']
                m = self.org.get(senderAid)
                senderAlias = m['alias'] if m else "Unknown Sender"
                sent = helping.fromIso8601(exn.ked['dt']).strftime("%Y-%m-%d %H:%M %Z")

                tab.add_row([f"{idx+start+1}", typ, f"{senderAlias}", attrs['m'], sent])

            print(f"Messages {start + 1} - {len(buffer)} / {len(self.notes)}")
            print(tab)

            a = self.session.prompt(f"[{start+1}-{len(buffer)}] View Message [N] Next  [P] Prev  [Q] Quit  > ")
            match a:
                case 'n':
                    if end < len(self.notes):
                        start = start + 10
                        end = end + 10
                case 'p':
                    if start != 0:
                        start = start - 10
                        end = start + 9
                case 'q':
                    break
                case None:
                    break
                case _:
                    try:
                        num = int(a)
                        if num in list(range(start+1, len(buffer)+1)):
                            note = buffer[num-1]
                            return show(note)
                    except ValueError:
                        break

    def do_show(self, num):
        try:
            num = int(num)
        except ValueError:
            print(f"invalid number {num}")
            return True

        if num < 0 or num > len(self.notes) - 1:
            print(f"number {num} out of bounds")

        print("\n\n")
        print(self.notes[num])

    def show_grant(self, note):
        attrs = note.attrs
        said = attrs['d']
        exn, pathed = exchanging.cloneMessage(self.hby, said)

        sad = exn.ked['e']["acdc"]
        iss = exn.ked['e']['iss']

        schema = sad['s']
        scraw = self.mbx.verifier.resolver.resolve(schema)
        if not scraw:
            raise kering.ConfigurationError("Credential schema {} not found".format(schema))

        schemer = scheming.Schemer(raw=scraw)
        creder = self.rgy.reger.creds.get(keys=(sad['d'],))
        if creder is None:
            accepted = f"No {terming.Colors.FAIL}{terming.Symbols.FAILED}{terming.Colors.ENDC}"
        else:
            accepted = f"Yes {terming.Colors.OKGREEN}{terming.Symbols.CHECKMARK}{terming.Colors.ENDC}"
        print(f"Credential {sad['d']}:")
        print(f"    Type: {schemer.sed['title']}")
        print(
            f"    Status: Granted {terming.Colors.OKGREEN}{terming.Symbols.CHECKMARK}{terming.Colors.ENDC}")
        print(f"    Issued by {sad['i']}")
        print(f"    Issued on {iss['dt']}")
        print(f"    Already accepted? {accepted}")

        a = self.session.prompt(f" [A] Admit  [S] Spurn  [Q] Quit  > ")
        match a:
            case 'a':
                self.admit(note)
            case 's':
                self.spurn(note)
            case 'q':
                return True
            case None:
                return True

    def admit(self, note):
        print("admiting", note)

    def spurn(self, note):
        print("spuring", note)
