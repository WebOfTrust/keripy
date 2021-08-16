

def addRotationArgs(parser):
    parser.add_argument('--sith', '-s', help='', default=None, type=int, required=False)
    parser.add_argument('--toad', '-t', help='', default=None, type=int, required=False)
    parser.add_argument('--witnesses', '-w', help='New set of witnesses, replaces all existing witnesses.  Can appear '
                                                  'multiple times', metavar="<prefix>", default=[],
                        action="append", required=False)
    parser.add_argument('--witness-cut', '-c', help='Witnesses to remove.  Can appear multiple times', metavar="<prefix>",
                        default=[],
                        action="append", required=False)
    parser.add_argument('--witness-add', '-a', help='Witnesses to add.  Can appear multiple times', metavar="<prefix>",
                        default=[],
                        action="append", required=False)
    parser.add_argument('--data', '-d', help='Anchor data, \'@\' allowed', default=[], action="store", required=False)
