# -*- encoding: utf-8 -*-
"""
KERI
keri.mailbox module

"""
import datetime
import sys
import traceback

from hio.base import doing
from hio.help import decking

from .. import help, kering
from ..app import httping, agenting
from ..app.habbing import GroupHab
from ..db import basing
from ..help import helping

logger = help.ogler.getLogger()

class Poller(doing.DoDoer):
    """
    Polls remote SSE endpoint for event that are KERI messages to be processed

    """

    def __init__(self, hab, witness, topics, msgs=None, retry=1000, **kwa):
        """
        Returns doist compatible doing.Doer that polls a witness for mailbox messages
        as SSE events

        Parameters:
            hab:
            witness:
            topics:
            msgs:

        """
        self.hab = hab
        self.pre = hab.pre
        self.witness = witness
        self.topics = topics
        self.retry = retry
        self.msgs = None if msgs is not None else decking.Deck()
        self.times = dict()

        doers = [doing.doify(self.eventDo)]

        super(Poller, self).__init__(doers=doers, **kwa)

    def eventDo(self, tymth=None, tock=0.0):
        """
        Returns:
           doifiable Doist compatible generator method

        Usage:
            add result of doify on this method to doers list
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        witrec = self.hab.db.tops.get((self.pre, self.witness))
        if witrec is None:
            witrec = basing.TopicsRecord(topics=dict())

        while self.retry > 0:
            try:
                client, clientDoer = agenting.httpClient(self.hab, self.witness)
            except kering.MissingEntryError as e:
                traceback.print_exception(e, file=sys.stderr)  # logging
                yield self.tock
                continue

            self.extend([clientDoer])

            topics = dict()
            q = dict(pre=self.pre, topics=topics)
            for topic in self.topics:
                if topic in witrec.topics:
                    topics[topic] = witrec.topics[topic] + 1
                else:
                    topics[topic] = 0

            if isinstance(self.hab, GroupHab):
                msg = self.hab.mhab.query(pre=self.pre, src=self.witness, route="mbx", query=q)
            else:
                msg = self.hab.query(pre=self.pre, src=self.witness, route="mbx", query=q)

            httping.createCESRRequest(msg, client, dest=self.witness)

            while client.requests:
                yield self.tock

            created = helping.nowUTC()
            while True:

                now = helping.nowUTC()
                if now - created > datetime.timedelta(seconds=30):
                    self.remove([clientDoer])
                    break

                while client.events:
                    evt = client.events.popleft()
                    if "retry" in evt:
                        self.retry = evt["retry"]
                    if "id" not in evt or "data" not in evt or "name" not in evt:
                        logger.error(f"bad mailbox event: {evt}")
                        continue
                    idx = evt["id"]
                    msg = evt["data"]
                    tpc = evt["name"]

                    if not idx or not msg or not tpc:
                        logger.error(f"bad mailbox event: {evt}")
                        continue

                    self.msgs.append(msg.encode("utf=8"))
                    yield self.tock

                    witrec.topics[tpc] = int(idx)
                    self.times[tpc] = helping.nowUTC()
                    self.hab.db.tops.pin((self.pre, self.witness), witrec)

                yield 0.25
            yield self.retry / 1000
