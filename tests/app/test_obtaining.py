from keri.app import obtaining


def test_getwitness():

    loc = obtaining.getwitnessbyprefix("B8NkPDTGELcUDH-TBCEjo4dpCvUnO_DnOSNEaNlL--4M")
    assert loc.ip4 == "127.0.0.1"
    assert loc.tcp == 5631
    loc = obtaining.getwitnessbyprefix("BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo")
    assert loc.ip4 == "127.0.0.1"
    assert loc.tcp == 5632
    loc = obtaining.getwitnessbyprefix("BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw")
    assert loc.ip4 == "127.0.0.1"
    assert loc.tcp == 5633
    loc = obtaining.getwitnessbyprefix("Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c")
    assert loc.ip4 == "127.0.0.1"
    assert loc.tcp == 5634


def test_getendpointbyprefix():

    loc = obtaining.getendpointbyprefix("EhYpYZSUAtiEurF7XngDB2mII2khY9ktlfqKHd1NHfNY")
    assert loc.ip4 == "127.0.0.1"
    assert loc.tcp == 5629
    assert loc.http == 0
    loc = obtaining.getendpointbyprefix("ExwBAYqvPpaPpGmBCixIiC_xpcDto8YUxLoNJgE2FOKo")
    assert loc.ip4 == "127.0.0.1"
    assert loc.tcp == 5621
    assert loc.http == 5620



if __name__ == '__main__':
    test_getwitness()