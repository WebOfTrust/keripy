from keri.app import habbing, delegating


def test_boatswain_proxy():
    with habbing.openHby(name="deltest", temp=True) as eeHby, \
            habbing.openHby(name="deltest", temp=True) as orHby:
        orHab = orHby.makeHab("delegator", transferable=True)
        assert orHab.pre == "E5dAsRrMTpVafiQ3k4fOsATAqO3XgJCotZ42UHZXOpBE"
        eeHab = eeHby.makeHab("del", transferable=True, delpre=orHab.pre,
                              wits=["BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo",
                                    "BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw",
                                    "Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c"]

                              )
        assert eeHab.pre == "EjpMeAft7BSVfD3Z4HlSAWrCfvim87Z1kMHDg9-xNbl0"

        boats = delegating.Boatswain(hby=eeHby)
        phab = boats.proxy("deltest", eeHab.kever)

        assert phab.pre == "EArIzjKa0AeQrmgx8vxkVmRHrPcUck-6IeK4av-moN8I"
        assert phab.kever.wits == eeHab.kever.wits
        assert phab.kever.toad == eeHab.kever.toad
        assert phab.kever.tholder.sith == eeHab.kever.tholder.sith
