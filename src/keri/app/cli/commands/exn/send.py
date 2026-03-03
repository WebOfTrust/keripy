# -*- encoding: utf-8 -*-
"""Generic send command (EXN only)

Example:
    kli exn send --sender alice --recipient bob --route /challenge/response --topic challenge --data words='["red","blue"]'

Data formats:
    --data key=value               (repeatable)
    --data '{"json":"object"}'     (single JSON object)
    --data @/path/to/data.json     (JSON object loaded from file)
"""
import argparse
from typing import List

from hio.base import doing

from .... import habbing, forwarding, organizing
from ...common import existing
from ...common.parsing import Parsery, parseDataItems
from ....habbing import GroupHab
from .....peer import exchanging

parser = argparse.ArgumentParser(
    description="Send a generic EXN message with user-supplied route/topic/data",
    parents=[Parsery.keystore()],
)
parser.set_defaults(handler=lambda args: send(args))

parser.add_argument(
    "--sender", "-s", help="local identifier alias (sender)", required=True
)
parser.add_argument(
    "--recipient", "-r", help="recipient alias/contact or AID", required=True
)
parser.add_argument(
    "--route", help="message route, e.g. /challenge/response", required=True
)
parser.add_argument(
    "--topic",
    help="postman topic for forwarded messages, defaults to first segment of route, e.g. challenge/credential",
)
parser.add_argument(
    "--data",
    help="message data/payload: key=value (repeatable), JSON object string, or @file.json",
    action="append",
    default=[],
)


def send(args):
    name = args.name
    base = args.base
    bran = args.bran

    doer = SendDoer(
        name=name,
        base=base,
        bran=bran,
        sender=args.sender,
        recipient=args.recipient,
        route=args.route,
        topic=args.topic,
        data_items=args.data,
    )
    return [doer]


def resolveRecipient(org: organizing.Organizer, hby, recipient: str) -> str:
    """
    recipient may be:
      - AID (already in kevers)
      - contact alias in organizer
    """
    if recipient in hby.kevers:
        return recipient

    matches = org.find("alias", recipient)
    if len(matches) != 1:
        raise ValueError(f"invalid recipient {recipient}")
    return matches[0]["id"]


class SendDoer(doing.DoDoer):
    """
    Generic sender for EXN messages (exchanging.exchange + endorse)
    """

    def __init__(
        self,
        name: str,
        base: str,
        bran: str,
        sender: str,
        recipient: str,
        route: str,
        topic: str | None,
        data_items: List[str],
    ):
        self.sender = sender
        self.recipient = recipient
        self.route = route
        self.topic = topic if topic else route.strip("/").split("/")[0]
        self.data_items = data_items

        self.hby = existing.setupHby(name=name, base=base, bran=bran)
        self.hbyDoer = habbing.HaberyDoer(habery=self.hby)
        self.org = organizing.Organizer(hby=self.hby)
        self.postman = forwarding.Poster(hby=self.hby)

        doers = [self.hbyDoer, self.postman, doing.doify(self.sendDo)]
        super(SendDoer, self).__init__(doers=doers)

    def sendDo(self, tymth, tock=0.0, **opts):
        self.wind(tymth)
        self.tock = tock
        _ = yield self.tock

        hab = self.hby.habByName(name=self.sender)
        if hab is None:
            raise ValueError(f"invalid sender alias {self.sender}")

        dest = resolveRecipient(self.org, self.hby, self.recipient)
        data = parseDataItems(self.data_items)

        senderHab = hab.mhab if isinstance(hab, GroupHab) else hab

        payload = dict(data)
        exn, _ = exchanging.exchange(
            route=self.route, payload=payload, sender=senderHab.pre
        )
        ims = hab.endorse(serder=exn, last=False, pipelined=False)
        del ims[: exn.size]
        self.postman.send(
            src=senderHab.pre,
            dest=dest,
            topic=self.topic,
            serder=exn,
            attachment=ims,
        )

        while not self.postman.cues:
            yield self.tock

        print(f"Sent EXN message")
        print(exn.pretty())

        self.remove([self.hbyDoer, self.postman])
        return
