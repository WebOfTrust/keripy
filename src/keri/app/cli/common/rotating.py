def addRotationArgs(parser):
    parser.add_argument('--isith', '-i', help='signing threshold for the rotation event', default=None,
                        required=False)
    parser.add_argument('--nsith', '-x', help='signing threshold for the next rotation event', default=None,
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





