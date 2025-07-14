from keri.app import habbing
from keri.core import kraming, serdering
from keri.help import helping


def test_timeliness(monkeypatch):

    def mockNowIso8601():
        return "2021-06-27T21:26:21.233257+00:00"

    monkeypatch.setattr(helping, "nowIso8601", mockNowIso8601)

    with habbing.openHab(name="kramTest", base="test", salt=b'0123456789abcdeg') as (hby, hab):

        tc = kraming.TimelinessCache(db=hby.db, defaultDriftSkew=1_000_000, defaultWindowSize=1_000_000)

        assert tc.defaultWindowSize == 1_000_000
        assert tc.defaultDriftSkew == 1_000_000

        def create_test_serder(ilk, timestamp=None, route=None, sourceAid=hab.pre,
                               message_id="EckOnHB11J4H9q16I3tN8DdpNXnCiP5QJQ7yvkWqTDdA", qBlock=None, routeParams=None):
            """Helper to create a test serder with specified parameters"""
            if timestamp is None:
                timestamp = helping.nowIso8601()

            sad = {
                "v": "KERI10JSON00011c_",
                "t": ilk,
                "i": sourceAid,
                "dt": timestamp,
            }

            if route:
                if routeParams:
                    route += "?" + "&".join([f"{k}={v}" for k, v in routeParams.items()])
                sad["r"] = route

            if qBlock:
                sad["q"] = qBlock

            return serdering.SerderKERI(sad=sad, makify=True)

        current_time = helping.nowIso8601()

        routeParams = {"transaction_type": "credential"}

        offerQBlock = {
            "issuer": f"did:keri:{hab.pre}",
            "output_descriptors": ["EckOnHB11J4H9q16I3tN8DdpNXnCiP5QJQ7yvkWqTDdA"],
            "format": {"cesr": {"proof_type": ["Ed25519Signature2018"]}}
        }

        offerSerder = create_test_serder(
            ilk="exn",
            timestamp=current_time,
            route="/credential/offer",
            routeParams=routeParams,
            qBlock=offerQBlock
        )

        # Cache first entry
        isValid, reason = tc.checkMessageTimeliness(offerSerder)
        assert isValid, f"Credential offer message should be valid, got: {reason}"
        assert reason == "Message accepted, new entry"

        def mockNowIso8601Later():
            return "2021-06-27T21:26:24.233257+00:00"

        monkeypatch.setattr(helping, "nowIso8601", mockNowIso8601Later)

        offerSerder2 = create_test_serder(ilk="exn", timestamp=mockNowIso8601Later(), route="/credential/offer",
                           sourceAid="BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo")

        # Cache new entry
        isValid, reason = tc.checkMessageTimeliness(offerSerder2)
        assert isValid, f"Credential offer message should be valid, got: {reason}"
        assert reason == "Message accepted, new entry"

        # Attempt to cache first entry again
        isValid, reason = tc.checkMessageTimeliness(offerSerder)
        assert not isValid, f"Credential offer message should be invalid, got: {reason}"

        # Prune only the entry with a time outside the window
        assert tc.pruneCache() == 1