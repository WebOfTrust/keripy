from keri.vdr.viring import Registry


class Issuer:
    """

    """
    def __init__(self, hab, name="test", reg=None):
        """
        Initialize Instance

        Parameters:
            name is the alias for this issuer
            hab is Habitat instance of local controller's context
            reg is Registry instance for controller's credentials

        """
        self.hab = hab
        self.name = name
        self.reg = reg if reg is not None else Registry(name=name)

    def issue(self):
        print("issuing credential", self.name)

    def revoke(self):
        print("revoking credential", self.name)

    def rotate(self):
        print("rotating registry backer list", self.name)

