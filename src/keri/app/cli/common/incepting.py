# -*- encoding: utf-8 -*-
"""
keri.app..cli.common.incepting module

"kli incept" command configuration options
"""


def addInceptingArgs(parser):
    """
    Add command line arguments for each of the properties in InceptOptions
    """
    parser.add_argument('--transferable', '-tf', action="store_true",
                        help='Whether the prefix is transferable or non-transferable')
    parser.add_argument('--wits',         '-w', default=[], required=False, action="append", metavar="<prefix>",
                        help='New set of witnesses, replaces all existing witnesses.  Can appear multiple times')
    parser.add_argument('--toad',         '-t', default=None, required=False, type=int,
                        help='int or str hex of witness threshold (threshold of accountable duplicity)',)
    parser.add_argument('--icount',       '-ic', default=None, required=False,
                        help='incepting key count for number of keys used for inception')
    parser.add_argument('--isith',        '-s', default=None, required=False,
                        help='signing threshold for the inception event')
    parser.add_argument('--ncount',       '-nc', default=None, required=False,
                        help='next key count for number of next keys used on first rotation')
    parser.add_argument('--nsith',        '-x', default=None, required=False,
                        help='signing threshold for the next rotation event',)
    parser.add_argument('--est-only',     '-e', type=bool, default=None,
                        help='only allow establishment events in KEL for this prefix')
    parser.add_argument('--data',         '-d', default=None, required=False, action="store",
                        help='Anchor data, \'@\' allowed',)

