# -*- encoding: utf-8 -*-
"""
KERI
keri.app.apping module

"""
import os
import shutil
import json
from dataclasses import dataclass, asdict
from typing import Type

import cbor2
import msgpack
import lmdb

from hio.base import doing
from hio.core.serial import serialing

from .. import kering
from .. import help
from ..help import helping
from ..db import dbing, koming
from . import keeping
from ..core import coring, eventing
from . import habbing


logger = help.ogler.getLogger()


def clean(orig, kvy=None):
    """
    Clean orig (original) database by creating re-verified cleaned cloned copy
    and then replacing original with cleaned cloned controller

    Database usage should be offline during cleaning as it will be cloned in
    readonly mode

    Parameters:
        orig (Baser): original instance to clean
        kvy (eventing.Kevery): instance to process cloned events. Othewise uses
            default


    """
    with dbing.openDB(name=orig.name,
                      temp=orig.temp,
                      headDirPath=orig.headDirPath,
                      dirMode=orig.dirMode,
                      clean=True) as copy:

        with dbing.reopenDB(db=orig, reuse=True, readonly=True):  # reopen orig readonly
            if not os.path.exists(orig.path):
                raise ValueError("Error cloning, no orig at {}."
                                 "".format(orig.path))

            if not kvy:  # new kvy for clone
                kvy = eventing.Kevery()  # promiscuous mode
            kvy.db = copy
            psr = eventing.Parser(kvy=kvy)

            # Revise in future to NOT parse msgs but to extract the processed
            # objects so can pass directly to kvy.processEvent()
            # need new method cloneObjAllPreIter()
            # process event doesn't capture exceptions so we can more easily
            # detect in the cloning that some events did not make it through
            for msg in orig.cloneAllPreIter():  # clone orig into copy
                psr.processOne(ims=msg)

            # clone habitat name prefix Komer subdb
            # okdb = koming.Komer(db=orig, schema=habbing.HabitatRecord, subdb='habs.')  # orig
            copy.habs = koming.Komer(db=copy, schema=habbing.HabitatRecord, subdb='habs.')  # copy
            for keys, data in orig.habs.getItemIter():
                copy.habs.put(keys=keys, data=data)

            if not copy.habs.get(keys=(orig.name, )):
                raise ValueError("Error cloning, missing orig name={} subdb."
                                 "".format(orig.name))

        # remove orig db directory replace with clean clone copy
        if os.path.exists(orig.path):
            shutil.rmtree(orig.path)

        dst = shutil.move(copy.path, orig.path)  # move copy back to orig
        if not dst:  #  move failed leave new in place so can manually fix
            raise ValueError("Error cloning, unable to move {} to {}."
                             "".format(copy.path, orig.path))

        with dbing.reopenDB(db=orig, reuse=True):  # make sure can reopen
            if not isinstance(orig.env, lmdb.Environment):
                raise ValueError("Error cloning, unable to reopen."
                                 "".format(orig.path))

    # clone success so remove if still there
    if os.path.exists(copy.path):
        shutil.rmtree(copy.path)


class Consoler(doing.Doer):
    """
    Manages command console
    """

    def __init__(self, console=None, **kwa):
        """

        """
        super(Consoler, self).__init__(**kwa)
        self.console = console if console is not None else serialing.Console()


    def recur(self, tyme):
        """
        Do 'recur' context actions. Override in subclass.
        Regular method that perform repetitive actions once per invocation.
        Assumes resource setup in .enter() and resource takedown in .exit()
        (see ReDoer below for example of .recur that is a generator method)

        Returns completion state of recurrence actions.
           True means done False means continue

        Parameters:
            Doist feeds its .tyme through .send to .do yield which passes it here.


        .recur maybe implemented by a subclass either as a non-generator method
        or a generator method. This stub here is as a non-generator method.
        The base class .do detects which type:
            If non-generator .do method runs .recur method once per iteration
                until .recur returns (True)
            If generator .do method runs .recur with (yield from) until .recur
                returns (see ReDoer for example of generator .recur)

        """
        line = self.console.get()  # process one line of input
        if not line:
            return False
        chunks = line.lower().split()
        if not chunks:  # empty list
            self.console.put("Try one of: l[eft] r[ight] w[alk] s[top]\n")
            return False
        command = None
        verb = chunks[0]

        if verb.startswith('r'):
            command = ('turn', 'right')

        elif verb.startswith('l'):
            command = ('turn', 'left')

        elif verb.startswith('w'):
            command = ('walk', 1)

        elif verb.startswith('s'):
            command = ('stop', '')

        else:
            self.console.put("Invalid command: {0}\n".format(verb))
            self.console.put("Try one of: t[urn] s[top] w[alk]\n")
            return False

        self.console.put("Did: {} {}\n".format(command[0], command[1]))

        return (False)

