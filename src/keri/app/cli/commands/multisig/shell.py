import argparse
import cmd
import fractions
import json
import os

from hio.base import doing
from keri.app import connecting, apping
from keri.app.cli.common import existing
from keri.core import coring

parser = argparse.ArgumentParser(description='Initialize a prefix')
parser.set_defaults(handler=lambda args: handler(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--passcode', '-p', help='21 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)  # passcode => bran

parser.add_argument('--static-threshold', '-t', help='Specify this to switch to using one static number as the signing'
                                                     'threshold for the multisig group AID',
                    dest="static", action="store_true")  # passcode => bran


def handler(args):
    """ Command line list handler

    """
    kwa = dict(args=args)
    return [doing.doify(kims, **kwa)]


def kims(tymth, tock=0.0, **opts):
    _ = (yield tock)

    args = opts["args"]
    name = args.name
    base = args.base
    bran = args.bran
    static = args.static

    with existing.existingHby(name=name, base=base, bran=bran) as hby:
        org = connecting.Organizer(hby=hby)
        contacts = org.list()
        MultiSigShell(hby, contacts, static).cmdloop()
        return True


DEFAULT_PROMPT = '(kims) '


class MultiSigShell(cmd.Cmd):
    intro = 'Welcome to the KERI interactive multisig shell.   Type help or ? to list commands.\n'
    prompt = DEFAULT_PROMPT
    add_cmds = ["participant", "witness", "local"]

    def __init__(self, hby, contacts, static=False):
        self.hby = hby
        self.static = static
        self.transferable = []
        self.nontrans = []
        for contact in contacts:
            prefixer = coring.Prefixer(qb64=contact["id"])
            if prefixer.transferable:
                self.transferable.append(contact)
            else:
                self.nontrans.append(contact)

        self.alias = None
        self.wits = []
        self.delegator = None
        self.participants = []
        self.weights = []
        self.toad = None
        self.thold = None
        self.sith = None

        super(MultiSigShell, self).__init__()

    def reset(self):
        self.alias = None
        self.wits = []
        self.delegator = None
        self.participants = []
        self.toad = None
        self.thold = None
        self.sith = None

    # ----- basic multisig commands -----
    def do_show(self, _):
        """ Print the current start of the multisig group configuration file """
        try:
            self.validate()
        except ValueError as e:
            print(f"Invalid configuration: {e.args[0]}")
            return

        print(json.dumps(self.incept, indent=2))

    def do_delegator(self, arg):
        """ Set the delegator to the AID of the provided contact """
        alias = arg.strip()
        aid = None
        for contact in self.transferable:
            if contact["alias"] == alias:
                aid = contact["id"]
        if aid is not None:
            self.delegator = aid
            print(f"{alias} AID {aid} set as delegator")

    def do_threshold(self, arg):
        """ Set the static integer threshold of the AID.  Must be greater than 0 and less than or equal to the number
        of participants """
        if not self.static:
            print("Using fractionally weighted thresholds, invalid command")
            return

        self.thold = arg

    def complete_delegator(self, text, line, start_index, end_index):
        if text:
            return [
                contact["alias"] for contact in self.transferable if contact["alias"].startswith(text)
            ]
        else:
            return [contact["alias"] for contact in self.transferable]

    def do_add(self, arg):
        """ Add [local | participant | witness ] to the current configuration """
        if arg.startswith("local"):
            alias = arg.removeprefix("local").strip()
            aid = None
            for hab in list(self.hby.habs.values()):
                if hab.name == alias:
                    aid = hab.pre
            if aid is not None:
                self.participants.append(aid)
                print(f"{alias} AID {aid} added to participants")
                if not self.static:
                    self.prompt = "\tEnter weight: "

        elif arg.startswith("participant"):
            alias = arg.removeprefix("participant").strip()
            aid = None
            for contact in self.transferable:
                if contact["alias"] == alias:
                    aid = contact["id"]
            if aid is not None:
                self.participants.append(aid)
                print(f"{alias} AID {aid} added to participants")
                if not self.static:
                    self.prompt = "\tEnter weight: "

        elif arg.startswith("witness"):
            alias = arg.removeprefix("witness").strip()
            aid = None
            for contact in self.nontrans:
                if contact["alias"] == alias:
                    aid = contact["id"]
            if aid is not None:
                self.wits.append(aid)
                print(f"{alias} AID {aid} added to witnesses")

        else:
            print(f"unknown add command {arg}")

    def complete_add(self, text, line, start_index, end_index):
        if line.startswith("add local"):
            if text:
                return [
                    hab.name for hab in list(self.hby.habs.values()) if hab.name.startswith(text)
                ]
            else:
                return [hab.name for hab in list(self.hby.habs.values())]
        elif line.startswith("add participant"):
            if text:
                return [
                    contact["alias"] for contact in self.transferable if contact["alias"].startswith(text)
                ]
            else:
                return [contact["alias"] for contact in self.transferable]
        elif line.startswith("add witness"):
            if text:
                return [
                    contact["alias"] for contact in self.nontrans if contact["alias"].startswith(text)
                ]
            else:
                return [contact["alias"] for contact in self.nontrans]
        else:
            if text:
                return [
                    c for c in self.add_cmds if c.startswith(text)
                ]
            else:
                return self.add_cmds

    def do_save(self, arg):
        """ Save multisig configureation to file which can be passed to `kli multisig incept` """

        if arg == "":
            print("file name is required")
            return

        if os.path.exists(arg):
            print(f"{arg} exists, will not overwrite.")
            return

        try:
            self.validate()
        except ValueError as e:
            print(f"Invalid configuration: {e.args[0]}")
            return

        with open(arg, 'w', encoding="utf-8") as f:
            json.dump(self.incept, f, indent=2)

    def do_exit(self, _):
        """ Exit without saving """
        self.close()
        return True

    @property
    def incept(self):
        incept = dict()
        if self.delegator is not None:
            incept["delpre"] = self.delegator

        incept["aids"] = self.participants
        incept["transferable"] = True
        incept["wits"] = self.wits
        incept["toad"] = self.toad or len(self.wits)

        if self.static:
            incept["isith"] = self.thold if self.thold is not None else f"{len(self.participants)}"
        else:
            incept["isith"] = self.weights

        incept["nsith"] = incept.get("isith")

        return incept

    def precmd(self, line):
        if self.prompt == "\tEnter weight: ":
            try:
                if isNotValidFloat(line):
                    print("Float syntax not supported")
                    return ""

                w = fractions.Fraction(line)
                if not 0 <= w <= 1:
                    print("Invalid fraction value")
                    return ""

            except ValueError:
                print("Invalid fraction value")
                return ""

            self.weights.append(str(w))
            self.prompt = DEFAULT_PROMPT
            return ""

        return line

    def emptyline(self) -> bool:
        return False

    @staticmethod
    def close():
        print("Closing")

    def validate(self):
        if len(self.participants) < 2:
            raise ValueError("not enough participants")

        local = 0
        for p in self.participants:
            if p in self.hby.habs:
                local += 1

        if local < 1:
            raise ValueError("you must have at least one local AID")

        if len(self.wits) < 1:
            raise ValueError("You need at least 1 witness")


def parse(arg):
    """ Convert a series of zero or more numbers to an argument tuple
    Args:
        arg:

    Returns:

    """
    return tuple(map(int, arg.split()))


def isNotValidFloat(s):
    try:
        f = float(s)
        return f not in (0, 1)
    except ValueError:
        return False
