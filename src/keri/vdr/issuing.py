from keri.core.coring import Counter, Seqner, CtrDex, MtrDex
from keri.core.eventing import SealEvent, TraitDex
from keri.vdr import eventing
from keri.vdr.viring import Registry


class Issuer:
    """

    """
    def __init__(self, hab, name="test", reg=None, tevers=None, noBackers=False, baks=None, toad=None,
                 estOnly=False):
        """
        Initialize Instance

        Parameters:
            name is the alias for this issuer
            hab is Habitat instance of local controller's context
            reg is Registry instance for controller's credentials
            tevers is a dict of Tever instances keys by qb64 prefix of registry
            noBackers is boolean True to allow specification of TEL specific backers
            backers is the initial list of backer prefixes qb64 for VCs in the Registry
            toad is int or str hex of witness threshold
            estOnly is boolean True for forcing rotation events for every TEL event.
        """

        self.estOnly = estOnly
        self.noBackers = noBackers
        self.hab = hab
        self.name = name
        self.regi = 0
        self.vcser = None

        self.reg = reg if reg is not None else Registry(name=name)
        self.tevers = tevers if tevers is not None else dict()



        # save backers locally for now.  will be managed by tever when implemented
        self.backers = baks if baks is not None else []

        self.cnfg = [TraitDex.NoBackers] if self.noBackers else []

        self.regser = eventing.incept(self.hab.pre,
                                      baks=self.backers,
                                      toad=toad,
                                      cnfg=self.cnfg,
                                      code=MtrDex.Blake3_256)
        self.regk = self.regser.pre

        rseal = SealEvent(self.regk, self.regser.ked["s"], self.regser.diger.qb64)

        if self.estOnly:
            self.ianchor = self.hab.rotate(data=[rseal._asdict()])
        else:
            self.ianchor = self.hab.interact(data=[rseal._asdict()])

        seal = SealEvent(i=self.hab.pre, s=self.hab.kever.sn, d=self.hab.kever.serder.dig)

        msg = self.messagize(serder=self.regser, seal=seal)

        # Process message in local Tevery when ready for now assign to self for testing
        self.incept = msg

    def rotate(self, toad=None, cuts=None, adds=None):
        """
        Rotate backer list for registry

        Parameters:
            toad is int or str hex of backer threshold after cuts and adds
            cuts is list of qb64 pre of backers to be removed from witness list
            adds is list of qb64 pre of backers to be added to witness list
        """

        if self.noBackers:
            raise ValueError("Attempt to rotate registry {} that does not support backers".format(self.regk))

        serder = eventing.rotate(dig=self.regser.dig, regk=self.regk, sn=self.regi+1, toad=toad, baks=self.backers,
                                 adds=adds, cuts=cuts)

        self.regser = serder
        rseal = SealEvent(self.regk, serder.ked["s"], self.regser.diger.qb64)

        tevt, kevt = self.anchorMsg(serder, rseal._asdict())

        # Process message in local Tevery when ready
        self.regi += 1

        return tevt, kevt

    def issue(self, vcdig):
        """

        Create and process an iss or bis message event

        Parameters:
            vcdig is hash digest of vc content qb64

        """

        if self.noBackers:
            serder = eventing.issue(vcdig=vcdig, regk=self.regk)
        else:
            serder = eventing.backerIssue(vcdig=vcdig, regk=self.regk, regsn=self.regi, regd=self.regser.diger.qb64)

        self.vcser = serder
        rseal = SealEvent(vcdig, self.vcser.ked["s"], self.vcser.diger.qb64)

        msg, kevt = self.anchorMsg(serder, rseal._asdict())

        # Process message in local Tevery when ready
        return msg, kevt

    def revoke(self, vcdig):
        """

        Create and process iss message event

        Parameters:
            vcdig is hash digest of vc content qb64

        """

        if self.noBackers:
            serder = eventing.revoke(vcdig=vcdig, regk=self.regk, dig=self.vcser.dig)
        else:
            serder = eventing.backerRevoke(vcdig=vcdig, regk=self.regk, regsn=self.regi, regd=self.regser.diger.qb64,
                                           dig=self.vcser.dig)

        rseal = SealEvent(vcdig, serder.ked["s"], serder.diger.qb64)

        msg, kevt = self.anchorMsg(serder, rseal._asdict())

        # Process message in local Tevery when ready
        return msg, kevt

    @staticmethod
    def messagize(serder, seal):
        msg = bytearray(serder.raw)
        msg.extend(Counter(CtrDex.EventSealQuadlets, count=1).qb64b)
        msg.extend(seal.i.encode("utf-8"))
        msg.extend(Seqner(sn=seal.s).qb64b)
        msg.extend(seal.d.encode("utf-8"))

        return msg

    def anchorMsg(self, serder, rseal):
        if self.estOnly:
            kevt = self.hab.rotate(data=[rseal])
        else:
            kevt = self.hab.interact(data=[rseal])

        seal = SealEvent(i=self.hab.pre, s=self.hab.kever.sn, d=self.hab.kever.serder.dig)
        tevt = self.messagize(serder=serder, seal=seal)

        return tevt, kevt
