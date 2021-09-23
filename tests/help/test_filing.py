# -*- encoding: utf-8 -*-
"""
tests.help.test_filing module

"""
import pytest

import os

from keri.help import filing

from keri import help


def test_filing():
    """
    Test Filer class
    """
    filer = filing.Filer(name="test")  # defaults
    assert filer.path == '/usr/local/var/keri/test'
    assert filer.opened
    assert os.path.exists(filer.path)
    assert not filer.file
    filer.close()
    assert not filer.opened
    assert filer.path == '/usr/local/var/keri/test'
    assert os.path.exists(filer.path)

    filer.reopen()  # reuse False so remake
    assert filer.opened
    assert filer.path == '/usr/local/var/keri/test'
    assert os.path.exists(filer.path)

    filer.reopen(reuse=True)  # reuse True and clear False so don't remake
    assert filer.opened
    assert filer.path == '/usr/local/var/keri/test'
    assert os.path.exists(filer.path)

    filer.reopen(reuse=True, clear=True)  # clear True so remake even if reuse
    assert filer.opened
    assert filer.path == '/usr/local/var/keri/test'
    assert os.path.exists(filer.path)

    filer.reopen(clear=True)  # clear True so remake
    assert filer.opened
    assert filer.path == '/usr/local/var/keri/test'
    assert os.path.exists(filer.path)

    filer.close(clear=True)
    assert not os.path.exists(filer.path)

    # Test Filer with file not dir

    filer = filing.Filer(name="test", base="conf", filed=True)  # defaults
    assert filer.path == '/usr/local/var/keri/conf/test.txt'
    assert filer.opened
    assert os.path.exists(filer.path)
    assert filer.file
    assert not filer.file.closed
    filer.close()
    assert not filer.opened
    assert filer.file.closed
    assert filer.path == '/usr/local/var/keri/conf/test.txt'
    assert os.path.exists(filer.path)

    filer.reopen()  # reuse False so remake
    assert filer.opened
    assert not filer.file.closed
    assert filer.path =='/usr/local/var/keri/conf/test.txt'
    assert os.path.exists(filer.path)

    filer.reopen(reuse=True)  # reuse True and clear False so don't remake
    assert filer.opened
    assert not filer.file.closed
    assert filer.path =='/usr/local/var/keri/conf/test.txt'
    assert os.path.exists(filer.path)

    filer.reopen(reuse=True, clear=True)  # clear True so remake even if reuse
    assert filer.opened
    assert not filer.file.closed
    assert filer.path =='/usr/local/var/keri/conf/test.txt'
    assert os.path.exists(filer.path)

    filer.reopen(clear=True)  # clear True so remake
    assert filer.opened
    assert not filer.file.closed
    assert filer.path =='/usr/local/var/keri/conf/test.txt'
    assert os.path.exists(filer.path)

    filer.close(clear=True)
    assert not os.path.exists(filer.path)



    """Done Test"""


if __name__ == "__main__":
    test_filing()


