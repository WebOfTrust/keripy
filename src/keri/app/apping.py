# -*- encoding: utf-8 -*-
"""
KERI
keri.app.apping module

"""
import os

from hio.base import doing
from hio.core import wiring
from hio.core.serial import serialing
from hio.core.tcp import clienting, serving

from .. import kering
from .. import help
from ..db import basing
from . import keeping, habbing, directing, configing

logger = help.ogler.getLogger()


def setupController(name="who", base="main", temp=False, sith=None, count=1,
                    curls=None, remote="eve", iurls=None):
    """
    Setup and return doers list to run controller

    Parameters:
        name is the name used for a specific habitat
        base is the name used for shared resources i.e. Baser and Keeper
               The habitat specific config file will be in base/name
        curls (list[str]): local controller's service endpoint urls
        remote (str): name of remote direct mode target
        iurls (list[str]):  oobi  urls

    Load endpoint database with named target urls including http not just tcp


    conf file json
    {
      dt: "isodatetime",
      curls: ["tcp://localhost:5620/"],
      iurls: ["tcp://localhost:5621/?name=eve"],
    }
    """


    if not curls:
        curls = ["ftp://localhost:5620/"]

    if not iurls:  # blind oobi
        iurls = [f"ftp://localhost:5621/?role={kering.Roles.peer}&name={remote}"]

    # setup databases  for dependency injection and config file
    ks = keeping.Keeper(name=base, temp=temp)  # not opened by default, doer opens
    ksDoer = keeping.KeeperDoer(keeper=ks)  # doer do reopens if not opened and closes
    db = basing.Baser(name=base, temp=temp)  # not opened by default, doer opens
    dbDoer = basing.BaserDoer(baser=db)  # doer do reopens if not opened and closes
    cf = configing.Configer(name=name, base=base, temp=temp)
    conf = cf.get()
    if not conf: # setup config file
        conf = dict(dt=help.nowIso8601(), curls=curls, iurls=iurls)
        cf.put(conf)


    # setup habitat
    hab = habbing.Habitat(name=name, ks=ks, db=db, cf=cf, temp=temp,
                          isith=sith, icount=count, )
    habDoer = habbing.HabitatDoer(habitat=hab)  # setup doer

    # setup wirelog to create test vectors
    path = os.path.dirname(__file__)
    path = os.path.join(path, 'logs')
    wl = wiring.WireLog(samed=True, filed=True, name=name, prefix='keri',
                        reopen=True, headDirPath=path)
    wireDoer = wiring.WireLogDoer(wl=wl)  # setup doer

    localPort = 5620
    remotePort = 5621
    # setup local directmode tcp server
    server = serving.Server(host="", port=localPort, wl=wl)
    serverDoer = serving.ServerDoer(server=server)  # setup doer
    directant = directing.Directant(hab=hab, server=server)
    # Reactants created on demand by directant


    # setup default remote direct mode client to remote party
    client = clienting.Client(host='127.0.0.1', port=remotePort, wl=wl)
    clientDoer = clienting.ClientDoer(client=client)  # setup doer
    director = directing.Director(hab=hab, client=client, tock=0.125)
    reactor = directing.Reactor(hab=hab, client=client)

    logger.info("\nDirect Mode controller %s:\nNamed %s on TCP port %s to port %s.\n\n",
                    hab.pre, hab.name, localPort, remotePort)

    return [ksDoer, dbDoer, habDoer, wireDoer, clientDoer, director, reactor,
            serverDoer, directant]



class Consoler(doing.Doer):
    """
    Manages command console
    """

    def __init__(self, db=None, console=None, **kwa):
        """

        """
        super(Consoler, self).__init__(**kwa)
        self.db = db if db is not None else basing.Baser()
        self.console = console if console is not None else serialing.Console()

    def enter(self):
        """"""
        if not self.console.reopen():
            raise IOError("Unable to open serial console.")

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

        # args = parser.parse_args(chunks)
        # if hasattr(args, "handler"):
        # args.handler(args)

        if not chunks:  # empty list
            self.console.put("Try one of: l[eft] r[ight] w[alk] s[top]\n")
            return False
        command = None
        verb = chunks[0]

        if verb.startswith(b'r'):
            command = ('turn', 'right')

        elif verb.startswith(b'l'):
            command = ('turn', 'left')

        elif verb.startswith(b'w'):
            command = ('walk', 1)

        elif verb.startswith(b's'):
            command = ('stop', '')

        else:
            self.console.put( "Invalid command: {0}\n".format(verb))
            self.console.put("Try one of: t[urn] s[top] w[alk]\n")
            return False

        self.console.put("Did: {} {}\n".format(command[0], command[1]).encode("utf-8"))

        return (False)

    def exit(self):
        """"""
        self.console.close()
