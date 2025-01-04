# -*- encoding: utf-8 -*-
"""
KERI
keri.mailbox module

"""
import time

from .. import help

logger = help.ogler.getLogger()

class Iterable:
    TimeoutMBX = 30000000

    def __init__(self, mbx, pre, topics, retry=5000):
        self.mbx = mbx
        self.pre = pre
        self.topics = topics
        self.retry = retry

    def __iter__(self):
        self.start = self.end = time.perf_counter()
        return self

    def __next__(self):
        if self.end - self.start < self.TimeoutMBX:
            if self.start == self.end:
                self.end = time.perf_counter()
                return bytearray(f"retry: {self.retry}\n\n".encode("utf-8"))

            data = bytearray()
            for topic, idx in self.topics.items():
                key = self.pre + topic
                for fn, _, msg in self.mbx.cloneTopicIter(key, idx):
                    data.extend(bytearray("id: {}\nevent: {}\nretry: {}\ndata: ".format(fn, topic, self.retry)
                                          .encode("utf-8")))
                    data.extend(msg)
                    data.extend(b'\n\n')
                    idx = idx + 1
                    self.start = time.perf_counter()

                self.topics[topic] = idx
            self.end = time.perf_counter()
            return data

        raise StopIteration

class QueryReplyIterable:

    def __init__(self, cues, mbx, said, retry=5000):
        self.mbx = mbx
        self.retry = retry
        self.cues = cues
        self.said = said
        self.iter = None

    def __iter__(self):
        return self

    def __next__(self):
        if self.iter is None:
            if self.cues:
                cue = self.cues.pull()
                serder = cue["serder"]
                if serder.said == self.said:
                    kin = cue["kin"]
                    if kin == "stream":
                        self.iter = iter(Iterable(mbx=self.mbx, pre=cue["pre"], topics=cue["topics"],
                                                         retry=self.retry))
                else:
                    self.cues.append(cue)

            return b''

        return next(self.iter)