# -*- encoding: utf-8 -*-
"""
tests.app.watching

"""
from dataclasses import asdict

import pytest

from keri import core
from keri.app import watching, habbing
from keri.app.watching import DiffState
from keri.core import coring
from keri.db.basing import KeyStateRecord, ObservedRecord


def test_diffstate():
    d0 = {'vn': [1, 0],
          'i': 'EZ-i0d8JZAoTNZH3ULaU6JR2nmwyvYAfSVPzhzS6b5CM',
          's': '0',
          'p': 'ElsHFkbZQjRb7xHnuE-wyiarIZ9j-1CEQ89I0E3WevcE',
          'd': 'EBiIFxr_o1b4x1YR21PblAFpFG61qDghqFBDyVSOXYW0',
          'f': '0',
          'dt': '2021-06-09T17:35:54.169967+00:00',
          'et': '2021-06-09T17:35:54.169967+00:00',
          'kt': '1',
          'k': ["D-HwiqmaETxls3vAVSh0xpXYTs94NUJX6juupWj_EgsA"],
          'nt': '1',
          'n': ["ED6lKZwg-BWl_jlCrjosQkOEhqKD4BJnlqYqWmhqPhaU"],
          'bt': '0',
          'b': [],
          'c': [],
          'ee': {
              's': '0',
              'd': 'EBiIFxr_o1b4x1YR21PblAFpFG61qDghqFBDyVSOXYW0',
              'br': [],
              'ba': []
          },
          'di': ''}

    ksr0 = KeyStateRecord(**d0)
    d1 = {'vn': [1, 0],
          'i': 'EZ-i0d8JZAoTNZH3ULaU6JR2nmwyvYAfSVPzhzS6b5CM',
          's': '0',
          'p': 'ElsHFkbZQjRb7xHnuE-wyiarIZ9j-1CEQ89I0E3WevcE',
          'd': 'Ey2pXEnaoQVwxA4jB6k0QH5G2Us-0juFL5hOAHAwIEkc',
          'f': '0',
          'dt': '2021-06-09T17:35:54.169967+00:00',
          'et': '2021-06-09T17:35:54.169967+00:00',
          'kt': '1',
          'k': ["DxVTxls3vAwiqmaEXYTs94NUJX6juVSh0xpupEgsAWj_"],
          'nt': '1',
          'n': ["ED6lKZwg-BWl_jlCrjosQkOEhqKD4BJnlqYqWmhqPhaU"],
          'bt': '0',
          'b': [],
          'c': [],
          'ee': {
              's': '0',
              'd': 'EBiIFxr_o1b4x1YR21PblAFpFG61qDghqFBDyVSOXYW0',
              'br': [],
              'ba': []
          },
          'di': ''}
    ksr1 = KeyStateRecord(**d1)

    wat = "BbIg_3-11d3PYxSInLN-Q9_T2axD6kkXd3XRgbGZTm6s"
    diffstate = watching.diffState(wat, ksr0, ksr1)

    # Sequence numbers are the same, digest different == duplicitous
    assert asdict(diffstate) == {'wit': 'BbIg_3-11d3PYxSInLN-Q9_T2axD6kkXd3XRgbGZTm6s',
                                 'state': 'duplicitous',
                                 'sn': 0, 'dig': 'Ey2pXEnaoQVwxA4jB6k0QH5G2Us-0juFL5hOAHAwIEkc'}

    # Same state == event
    diffstate = watching.diffState(wat, ksr0, ksr0)
    assert asdict(diffstate) == {'dig': 'EBiIFxr_o1b4x1YR21PblAFpFG61qDghqFBDyVSOXYW0',
                                 'sn': 0,
                                 'state': 'even',
                                 'wit': 'BbIg_3-11d3PYxSInLN-Q9_T2axD6kkXd3XRgbGZTm6s'}

    ksr1.s = "2"
    diffstate = watching.diffState(wat, ksr0, ksr1)

    # Sequence numbers are the same, digest different == duplicitous
    assert asdict(diffstate) == {'dig': 'Ey2pXEnaoQVwxA4jB6k0QH5G2Us-0juFL5hOAHAwIEkc',
                                 'sn': 2,
                                 'state': 'ahead',
                                 'wit': 'BbIg_3-11d3PYxSInLN-Q9_T2axD6kkXd3XRgbGZTm6s'}

    ksr0.s = "3"
    diffstate = watching.diffState(wat, ksr0, ksr1)

    # Sequence numbers are the same, digest different == duplicitous
    assert asdict(diffstate) == {'dig': 'Ey2pXEnaoQVwxA4jB6k0QH5G2Us-0juFL5hOAHAwIEkc',
                                 'sn': 2,
                                 'state': 'behind',
                                 'wit': 'BbIg_3-11d3PYxSInLN-Q9_T2axD6kkXd3XRgbGZTm6s'}


def test_adjudicator():
    default_salt = core.Salter(raw=b'0123456789abcdef').qb64
    with habbing.openHby(name="test", base="test", salt=default_salt) as hby:
        hab = hby.makeHab("test")
        assert hab.pre == "EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3"
        wat = "BbIg_3-11d3PYxSInLN-Q9_T2axD6kkXd3XRgbGZTm6s"
        saider = coring.Saider(qb64b=b'EClqKVJREM3MWKBqR2j712s3Z6rPxhqO-h-p8Ls6_9hQ')

        ksr = hab.kever.state()
        ksr0 = KeyStateRecord(**asdict(ksr))

        hab.db.knas.pin(keys=(hab.pre, wat), val=saider)
        hab.db.ksns.pin(keys=(saider.qb64, ), val=ksr0)
        hab.db.obvs.pin(keys=(hab.pre, wat, hab.pre), val=ObservedRecord(enabled=True))

        adj = watching.Adjudicator(hby=hby, hab=hab)

        adj.adjudicate(hab.pre, 1)
        assert len(adj.cues) == 1
        cue = adj.cues.pull()

        assert cue == {'cid': 'EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3',
                       'kin': 'keyStateConsistent',
                       'oid': 'EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3',
                       'states': [DiffState(wit='BbIg_3-11d3PYxSInLN-Q9_T2axD6kkXd3XRgbGZTm6s',
                                            state='even',
                                            sn=0,
                                            dig='EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3')],
                       'wids': {'BbIg_3-11d3PYxSInLN-Q9_T2axD6kkXd3XRgbGZTm6s'}}

        hab.rotate()

        adj.adjudicate(hab.pre, 1)
        assert len(adj.cues) == 1
        cue = adj.cues.pull()
        assert cue == {'behind': [DiffState(wit='BbIg_3-11d3PYxSInLN-Q9_T2axD6kkXd3XRgbGZTm6s',
                                            state='behind',
                                            sn=0,
                                            dig='EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3')],
                       'cid': 'EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3',
                       'kin': 'keyStateLagging',
                       'oid': 'EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3',
                       'wids': {'BbIg_3-11d3PYxSInLN-Q9_T2axD6kkXd3XRgbGZTm6s'}}

        ksr0.s = '1'
        hab.db.ksns.pin(keys=(saider.qb64, ), val=ksr0)
        adj.adjudicate(hab.pre, 1)
        assert len(adj.cues) == 1
        cue = adj.cues.pull()
        assert cue == {'cid': 'EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3',
                       'dups': [DiffState(wit='BbIg_3-11d3PYxSInLN-Q9_T2axD6kkXd3XRgbGZTm6s',
                                          state='duplicitous',
                                          sn=1,
                                          dig='EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3')],
                       'kin': 'keyStateDuplicitous',
                       'oid': 'EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3',
                       'wids': {'BbIg_3-11d3PYxSInLN-Q9_T2axD6kkXd3XRgbGZTm6s'}}

        with pytest.raises(ValueError):
            adj.adjudicate(hab.pre, 2)
