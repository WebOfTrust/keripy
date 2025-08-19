import pytest
from keri.app import habbing
from keri.core import kraming, serdering
from keri.help import helping
from keri import kering


def test_timeliness(monkeypatch, create_test_serder):

    def mockNowIso8601():
        return "2021-06-27T21:26:21.233257+00:00"

    monkeypatch.setattr(helping, "nowIso8601", mockNowIso8601)

    with habbing.openHab(name="kramTest", base="test", salt=b'0123456789abcdeg') as (hby, hab):

        tc = kraming.TimelinessCache(db=hby.db, defaultDriftSkew=1.0, defaultWindowSize=1.0)

        assert tc.defaultWindowSize == 1.0
        assert tc.defaultDriftSkew == 1.0

        # Set window parameters for the test AIDs
        tc.setWindowParameters(hab.pre, windowSize=1.0, driftSkew=1.0)


        current_time = helping.nowIso8601()

        offerSerder = create_test_serder(
            sourceAid=hab.pre,
            ilk="exn",
            timestamp=current_time,
            route="/credential/offer",
        )

        # Cache first entry
        isValid = tc.checkMessageTimeliness(offerSerder)
        assert isValid

        def mockNowIso8601Later():
            return "2021-06-27T21:26:23.233258+00:00"

        monkeypatch.setattr(helping, "nowIso8601", mockNowIso8601Later)

        offerSerder2 = create_test_serder(sourceAid="BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo",
                                          ilk="exn", timestamp=mockNowIso8601Later(), route="/credential/offer")

        # Cache new entry
        isValid = tc.checkMessageTimeliness(offerSerder2)
        assert isValid

        # Attempt to cache first entry again - this should now raise ValidationError
        with pytest.raises(kering.ValidationError):
            tc.checkMessageTimeliness(offerSerder)

        # Prune only the entry with a time outside the window
        assert tc.pruneCache() == 1