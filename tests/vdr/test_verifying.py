# -*- encoding: utf-8 -*-
"""
tests.vdr.verifying module

"""
from keri.app import habbing
from keri.vdr import verifying, issuing


def test_verifier_query():
    with habbing.openHab(name="test", transferable=True, temp=True) as hab:
        issuer = issuing.Issuer(hab=hab, name="test", temp=True)

        verfer = verifying.Verifier(hab=hab)
        msg = verfer.query(issuer.regk,
                           "Eb8Ih8hxLi3mmkyItXK1u55cnHl4WgNZ_RE-gKXqgcX4",
                           res="tels")
        assert msg == b'{"v":"KERI10JSON00009b_","t":"req","r":"tels",' \
                      b'"q":{"i":"Eb8Ih8hxLi3mmkyItXK1u55cnHl4WgNZ_RE-gKXqgcX4",' \
                      b'"ri":"EGZHiBoV8v5tWAt7yeTTln-CuefIGPhajTT78Tt2r9M4"}}-HABE4YPqsEOaPNaZxVIbY-Gx2bJgP' \
                      b'-c7AH_K7pEE-YfcI9E-AABAAhulhMW2RDUCHK5mxHryjlQ0i3HW_6CXbAGjNnHb9U9pq6N0C9DiavUbX6SgDsk' \
                      b'KIfoQLtV_EqTI_q9AyNAstAQ'


if __name__ == '__main__':
    test_verifier_query()
