# -*- encoding: utf-8 -*-
"""
KERI
keri.app.querying module

"""
from hio.base import doing

from .agenting import WitnessInquisitor


class QueryDoer(doing.DoDoer):
    """Manages a key state query for a given identifier prefix.

    Spawns a KeyStateNoticer doer to retrieve and monitor the key state
    of the target prefix via its witnesses.

    Attributes:
        hby (Habery): Habitat environment providing access to the key-value store and kevers.
        hab (Hab): Local habitat (signing identity) used as the query source.
        kvy (Kevery): Key event processor whose cue queue is monitored for key state events.
        pre (str): Qualified Base64 identifier prefix being queried.
    """

    def __init__(self, hby, hab, kvy, pre, **kwa):
        """Initialize QueryDoer.

        Args:
            hby (Habery): Habitat environment.
            hab (Hab): Local habitat used as the query source.
            kvy (Kevery): Key event processor providing the cue queue.
            pre (str): Qualified Base64 identifier prefix to query.
            **kwa: Additional keyword arguments forwarded to DoDoer.
        """
        self.hby = hby
        self.hab = hab
        self.kvy = kvy
        self.pre = pre

        doers = [KeyStateNoticer(hby=hby, hab=self.hab, pre=pre, cues=kvy.cues)]
        super(QueryDoer, self).__init__(doers=doers, **kwa)


class KeyStateNoticer(doing.DoDoer):
    """Monitors incoming key state notices (KSN) and triggers event log queries.

    Immediately issues a KSN query to the witnesses of the target prefix on
    construction. On each recur cycle, inspects the cue queue for a
    ``keyStateSaved`` event. When one arrives for the target prefix and the
    reported sequence number is ahead of the locally-known sequence number,
    a LogQuerier is spawned to fetch the missing key events, and the
    WitnessInquisitor is retired.

    Attributes:
        hby (Habery): Habitat environment providing access to the key-value store and kevers.
        hab (Hab): Local habitat used as the query source.
        pre (str): Qualified Base64 identifier prefix being monitored.
        cues (Deck): Shared cue queue produced by the Kevery event processor.
        witq (WitnessInquisitor): Witness query agent used to fetch the key state notice.
    """

    def __init__(self, hby, hab, pre, cues, **opts):
        """Initialize KeyStateNoticer and immediately issue a KSN witness query.

        Args:
            hby (Habery): Habitat environment.
            hab (Hab): Local habitat used as the query source.
            pre (str): Qualified Base64 identifier prefix to monitor.
            cues (Deck): Cue queue shared with the Kevery event processor.
            **opts: Additional keyword arguments forwarded to DoDoer.
        """
        self.hby = hby
        self.hab = hab
        self.pre = pre
        self.cues = cues
        self.witq = WitnessInquisitor(hby=self.hby)
        self.witq.query(src=self.hab.pre, pre=self.pre, r="ksn")

        super(KeyStateNoticer, self).__init__(doers=[self.witq], **opts)

    def recur(self, tyme, deeds=None):
        """Process one cycle of the key state monitoring loop.

        Drains one entry from the cue queue on each call. If the target
        prefix is not yet known locally, defers to the parent recur. When a
        ``keyStateSaved`` cue arrives for the target prefix and the remote
        sequence number exceeds the local one, a LogQuerier is added and the
        WitnessInquisitor is removed. Unrelated cues are returned to the queue.
        Returns True once the local key state is current, signalling completion.

        Args:
            tyme (float): Current elapsed time in seconds provided by the Doist.
            deeds (list | None): Optional list of scheduled deeds from the Doist.

        Returns:
            bool: True when the local key state is up-to-date and no further
                monitoring is needed; the parent DoDoer return value otherwise.
        """
        if self.pre in self.hby.kevers:
            kever = self.hby.kevers[self.pre]
        else:
            return super(KeyStateNoticer, self).recur(tyme, deeds)

        if self.cues:
            cue = self.cues.pull()
            match cue['kin']:
                case "keyStateSaved":
                    kcue = cue
                    ksn = kcue['ksn']  # key state notice dict
                    match ksn["i"]:
                        case self.pre:
                            if kever.sn < int(ksn["s"], 16):
                                # Add new doer here instead of cueing to a while loop
                                self.extend([LogQuerier(hby=self.hby, hab=self.hab, ksn=ksn)])
                                self.remove([self.witq])

                            else:
                                return True

                        case _:
                            self.cues.append(cue)

                case _:
                    self.cues.append(cue)

        return super(KeyStateNoticer, self).recur(tyme, deeds)


class LogQuerier(doing.DoDoer):
    """Fetches outstanding key event log entries from witnesses until the local
    key state matches the sequence number recorded in a key state notice.

    On construction, issues an event log query for the prefix identified in the
    supplied KSN. On each recur cycle, checks whether the locally-stored kever
    has reached the target sequence number; once it has, the WitnessInquisitor
    is retired and the doer signals completion.

    Attributes:
        hby (Habery): Habitat environment providing access to the key-value store and kevers.
        hab (Hab): Local habitat used as the query source.
        ksn (dict): Key state notice dictionary containing at least the identifier
            prefix (``"i"``) and target sequence number (``"s"`` as a hex string).
        witq (WitnessInquisitor): Witness query agent used to fetch the event log.
    """

    def __init__(self, hby, hab, ksn, **opts):
        """Initialize LogQuerier and immediately issue an event log witness query.

        Args:
            hby (Habery): Habitat environment.
            hab (Hab): Local habitat used as the query source.
            ksn (dict): Key state notice dictionary. Must contain ``"i"``
                (identifier prefix) and ``"s"`` (sequence number as a hex string).
            **opts: Additional keyword arguments forwarded to DoDoer.
        """
        self.hby = hby
        self.hab = hab
        self.ksn = ksn
        self.witq = WitnessInquisitor(hby=self.hby)
        self.witq.query(src=self.hab.pre, pre=self.ksn["i"])
        super(LogQuerier, self).__init__(doers=[self.witq], **opts)

    def recur(self, tyme, deeds=None):
        """Process one cycle of the event log fetch loop.

        Compares the local kever sequence number for the target prefix against
        the sequence number in the KSN. Once the local state has caught up,
        the WitnessInquisitor is removed and True is returned to signal
        completion.

        Args:
            tyme (float): Current elapsed time in seconds provided by the Doist.
            deeds (list | None): Optional list of scheduled deeds from the Doist.

        Returns:
            bool: True when the local kever has reached the target sequence
                number; the parent DoDoer return value otherwise.
        """
        kever = self.hab.kevers[self.ksn["i"]]
        if kever.sn >= int(self.ksn['s'], 16):
            self.remove([self.witq])
            return True

        return super(LogQuerier, self).recur(tyme, deeds)


class SeqNoQuerier(doing.DoDoer):
    """Queries witnesses for a specific key event by sequence number.

    Issues a targeted event log query for the given prefix and sequence number
    on construction. On each recur cycle, checks whether the local kever has
    reached the requested sequence number; once it has, the WitnessInquisitor
    is retired and the doer signals completion.

    Attributes:
        hby (Habery): Habitat environment providing access to the key-value store and kevers.
        hab (Hab): Local habitat used as the query source.
        pre (str): Qualified Base64 identifier prefix being queried.
        sn (int): Target sequence number to wait for (decimal).
        fn (int): First seen event number hint passed to the witness query (decimal).
        witq (WitnessInquisitor): Witness query agent used to fetch the event log.
    """

    def __init__(self, hby, hab, pre, sn, fn=None, wits=None, **opts):
        """Initialize SeqNoQuerier and immediately issue a sequence-number-targeted witness query.

        Args:
            hby (Habery): Habitat environment.
            hab (Hab): Local habitat used as the query source.
            pre (str): Qualified Base64 identifier prefix to query.
            sn (int): Target sequence number (decimal) to fetch.
            fn (int | None): First seen event number hint (decimal). Defaults to 0.
            wits (list[str] | None): Optional explicit list of witness prefixes to
                query. If None, witnesses are resolved from the identifier's key state.
            **opts: Additional keyword arguments forwarded to DoDoer.
        """
        self.hby = hby
        self.hab = hab
        self.pre = pre
        self.sn = sn
        self.fn = fn if fn is not None else 0
        self.witq = WitnessInquisitor(hby=self.hby)
        self.witq.query(src=self.hab.pre, pre=self.pre,
                        sn="{:x}".format(self.sn),
                        fn="{:x}".format(self.fn),
                        wits=wits)
        super(SeqNoQuerier, self).__init__(doers=[self.witq], **opts)

    def recur(self, tyme, deeds=None):
        """Process one cycle of the sequence number fetch loop.

        Returns False immediately if the target prefix is not yet present in
        the local kevers. Once the local kever sequence number meets or exceeds
        the target, the WitnessInquisitor is removed and True is returned to
        signal completion.

        Args:
            tyme (float): Current elapsed time in seconds provided by the Doist.
            deeds (list | None): Optional list of scheduled deeds from the Doist.

        Returns:
            bool: True when the local kever has reached the target sequence
                number; False if the prefix is not yet locally known;
                the parent DoDoer return value otherwise.
        """
        if self.pre not in self.hab.kevers:
            return False

        kever = self.hab.kevers[self.pre]
        if kever.sn >= self.sn:
            self.remove([self.witq])
            return True

        return super(SeqNoQuerier, self).recur(tyme, deeds)


class AnchorQuerier(doing.DoDoer):
    """Queries witnesses for a key event that seals a specific anchor.

    Issues an anchor-targeted event log query on construction. On each recur
    cycle, checks whether the local database contains a sealing event for the
    requested anchor; once found, the WitnessInquisitor is retired and the
    doer signals completion.

    Attributes:
        hby (Habery): Habitat environment providing access to the key-value store and kevers.
        hab (Hab): Local habitat used as the query source.
        pre (str): Qualified Base64 identifier prefix being queried.
        anchor (dict): Seal dictionary identifying the anchored event (e.g. a
            digest seal or event seal).
        witq (WitnessInquisitor): Witness query agent used to fetch the event log.
    """

    def __init__(self, hby, hab, pre, anchor, **opts):
        """Initialize AnchorQuerier and immediately issue an anchor-targeted witness query.

        Args:
            hby (Habery): Habitat environment.
            hab (Hab): Local habitat used as the query source.
            pre (str): Qualified Base64 identifier prefix to query.
            anchor (dict): Seal dictionary identifying the event to anchor on.
            **opts: Additional keyword arguments forwarded to DoDoer.
        """
        self.hby = hby
        self.hab = hab
        self.pre = pre
        self.anchor = anchor
        self.witq = WitnessInquisitor(hby=self.hby)
        self.witq.query(src=self.hab.pre, pre=self.pre, anchor=anchor)
        super(AnchorQuerier, self).__init__(doers=[self.witq], **opts)

    def recur(self, tyme, deeds=None):
        """Process one cycle of the anchor fetch loop.

        Returns False immediately if the target prefix is not yet present in
        the local kevers. Once the local database records a sealing event
        matching the anchor, the WitnessInquisitor is removed and True is
        returned to signal completion.

        Args:
            tyme (float): Current elapsed time in seconds provided by the Doist.
            deeds (list | None): Optional list of scheduled deeds from the Doist.

        Returns:
            bool: True when a matching sealing event has been stored locally;
                False if the prefix is not yet locally known;
                the parent DoDoer return value otherwise.
        """
        if self.pre not in self.hab.kevers:
            return False

        if self.hby.db.fetchLastSealingEventByEventSeal(self.pre, seal=self.anchor):
            self.remove([self.witq])
            return True

        return super(AnchorQuerier, self).recur(tyme, deeds)
