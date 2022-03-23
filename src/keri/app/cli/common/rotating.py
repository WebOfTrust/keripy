import json

from keri import kering


def addRotationArgs(parser):
    parser.add_argument('--sith', '-s', help='signing threshold for the rotation event', default=None, type=int,
                        required=False)
    parser.add_argument('--nsith', '-x', help='signing threshold for the next rotation event', default=None, type=int,
                        required=False)
    parser.add_argument('--toad', '-t', help='', default=None, type=int, required=False)
    parser.add_argument('--witnesses', '-w', help='New set of witnesses, replaces all existing witnesses.  Can appear '
                                                  'multiple times', metavar="<prefix>", default=[],
                        action="append", required=False)
    parser.add_argument('--witness-cut', '-c', help='Witnesses to remove.  Can appear multiple times',
                        metavar="<prefix>", default=[], dest="cuts", action="append", required=False)
    parser.add_argument('--witness-add', '-A', help='Witnesses to add.  Can appear multiple times', metavar="<prefix>",
                        default=[], action="append", required=False)
    parser.add_argument('--data', '-d', help='Anchor data, \'@\' allowed', default=None, action="store", required=False)


def loadData(args):
    """ Load data flag from command line namespace

    Parameters:
        args (Namespace): argparse command line namespace

    """
    if args.data is not None:
        try:
            if args.data.startswith("@"):
                f = open(args.data[1:], "r")
                data = json.load(f)
            else:
                data = json.loads(args.data)
        except json.JSONDecodeError:
            raise kering.ConfigurationError("data supplied must be value JSON to anchor in a seal")

        if not isinstance(data, list):
            data = [data]

    else:
        data = None

    return data
