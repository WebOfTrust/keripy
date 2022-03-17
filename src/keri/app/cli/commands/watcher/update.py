import argparse

from hio.base import doing

from keri import kering
from keri.app import habbing
from keri.core import coring

parser = argparse.ArgumentParser(description='Update set of watchers for this environment (Habitat)')
parser.set_defaults(handler=lambda args: handler(args))
parser.add_argument('--name', '-n', help='Human readable reference', required=True)
parser.add_argument('--watchers', '-w', help='New set of watchers, replaces all existing watchers.  Can appear '
                                              'multiple times', metavar="<prefix>", default=[],
                    action="append", required=False)
parser.add_argument('--cut', '-c', help='Watchers to remove.  Can appear multiple times', metavar="<prefix>",
                    default=[],
                    action="append", required=False)
parser.add_argument('--add', '-a', help='Watchers to add.  Can appear multiple times', metavar="<prefix>",
                    default=[],
                    action="append", required=False)


def handler(args):
    kwa = dict(args=args)
    return [doing.doify(updateWatchers, **kwa)]


def updateWatchers(tymth, tock=0.0, **opts):
    """ Command line status handler

    """
    _ = (yield tock)
    args = opts["args"]
    name = args.name

    try:
        with habbing.existingHabitat(name=name) as hab:

            habr = hab.db.habs.get(name)

            cuts = set(args.cut)
            adds = set(args.add)
            ewats = set(habr.watchers)
            if args.watchers:
                if args.add or args.cut:
                    raise kering.ConfigurationError("you can only specify witnesses or cuts and add")

                ewats = set(args.watchers)
            else:
                ewats |= adds
                ewats -= cuts

            for wat in ewats:
                pre = coring.Prefixer(qb64=wat)
                if pre.transferable:
                    raise ValueError("{} is an illegal watcher identifier, must be non-transferable"
                                     "".format(wat))

            habr.watchers = list(ewats)

            hab.db.habs.pin(name, habr)

            print("New Watcher Set:")
            for wat in habr.watchers:
                print("\t{}".format(wat))

    except kering.ConfigurationError:
        print(f"identifier prefix for {name} does not exist, incept must be run first", )
        return -1
    except ValueError as e:
        print(e.args[0])
        return -1

