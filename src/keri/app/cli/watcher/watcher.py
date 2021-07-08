# -*- encoding: utf-8 -*-
"""
keri.kli.commands.watcher module

"""
from hio.base import doing


class Watching(doing.Doist):
    def __init__(self, real=False, limit=None, doers=None, **kwa):
        self.publicKey = publicKey
        logging.debug(f'running with key %s', publicKey)
        self.hab = habbing.Habitat(name='klid', temp=False)

        klid = koming.Komer(db=self.hab.db, schema=KLIDRecord, subkey='klid.')
        klid.put((self.hab.pre,), KLIDRecord(
            publicKey=publicKey,
            started=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        ))

        doers = doers if doers is not None else []
        self.server = serving.Server(host='127.0.0.1', port=5678)
        serverDoer = serving.ServerDoer(server=self.server)
        servant = Servant(server=self.server, hab=self.hab)
        doers.extend([serverDoer, servant])

        super(Serving, self).__init__(doers=doers, **kwa)
