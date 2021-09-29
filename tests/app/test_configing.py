# -*- encoding: utf-8 -*-
"""
tests.app.configin module
"""

from keri.app import configing


def test_configer():
    """
    Test Configer class
    """
    cfr = configing.Configer()  # defaults
    cfr.close(clear=True)

    """Done Test"""


if __name__ == "__main__":
    test_configer()
