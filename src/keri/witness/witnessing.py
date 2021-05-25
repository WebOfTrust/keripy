from hio.base import doing
from hio.core.tcp import serving

from keri.base import directing, keeping

from .. import help
from ..db import dbing

logger = help.ogler.getLogger()


def setupWitness(name="witness", localPort=5620):

    wsith = 1

    hab = directing.Habitat(name=name, temp=False, transferable=False,
                            isith=wsith, icount=1,)
    logger.info("\nWitness- %s:\nNamed %s on TCP port %s.\n\n",
                hab.pre, hab.name, localPort)

    # setup doers
    ksDoer = keeping.KeeperDoer(keeper=hab.ks)  # doer do reopens if not opened and closes
    dbDoer = dbing.BaserDoer(baser=hab.db)  # doer do reopens if not opened and closes

    server = serving.Server(host="", port=localPort)
    serverDoer = doing.ServerDoer(server=server)
    directant = directing.Directant(hab=hab, server=server)

    return [ksDoer, dbDoer, directant, serverDoer]
