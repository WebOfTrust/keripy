# -*- encoding: utf-8 -*-
"""
keri.sit.siting module

Siter functionality

"""

from collections import namedtuple

from .. import Versionage, InvalidCodeError
from ..core import (MtrDex, DigDex, NonceDex, Noncer,  Ilker, Diger, Number)
from ..help import intToB64

Version = Versionage(major=0, minor=0)
MaxSpan = 256 # 256 bits or forks == leaf limb span
MaxSpanBytes = 32  # MaxSpan in bytes equivalent

Emptier = Noncer(nonce="")  # empty string
EmptyQb2 = Emptier.qb2
EmptyQb64 = Emptier.qb64


# kith is the data type string of part, i.e. ilk for node and leaf parts
Kithage = namedtuple("Kithage", "node leaf")
Kiths = Kithage(node='nod', leaf="lea")

"""NodeSaidage Doc String
Full Set of Fields (per tree and per part) used to compute node SAID.
Values are Matter instances. The said field is computed using the .qb64 property
of each instance

Per tree/part type field values:
    kith is Ilker instance encoding of node kith, value == Kiths.node
    tuid is Noncer instance encoding the tree unique identifier.
        This default is a CESR encoded crypto strength 16 byte (128 bit) value.
        Because it is CESR encoded other namespacing information can be included
        in a bigger tuid value as long as it includes at least 128 bits of entropy
Per node fields:
    said is Noncer instance digesting NodeSaidage content using SAID protocol
        said filled with dummy values for digest then replaced with computed SAID
        saided data = kith+tuid+saiddummy+span+limb+left+right
    span is Number instance encoding 2 byte int of number of MSbits in node limb
             min 0 for root to max of 255 = MaxSpan-1
    limb is Diger instance encoding of up to 256 bits with limb span MSbits
    left is Noncer instance encoding said of left child (node, leaf or empty)
    right is Noncer instance encoding said of right child (node, leaf or empty)
"""
NodeSaidage = namedtuple("NodeSaidage", "kith tuid said span limb left right")

"""LeafSaidage Doc String
Full Set of Fields (per tree and per part) used to compute leaf SAID.
Values are Matter instances. The said field is computed using the .qb64 property
of each instance

Per tree/part type field values:
    kith is Ilker instance encoding of leaf kith, value == Kiths.leaf
    tuid is Noncer instance encoding the tree unique identifier.
        This default is a CESR encoded crypto strength 16 byte (128 bit) value.
        Because it is CESR encoded other namespacing information can be included
        in a bigger tuid value as long as it includes at least 128 bits of entropy
Per leaf fields:
    said is Noncer instance digesting LeafSaidage content using SAID protocol
        said filled with dummy values for digest then replaced with computed SAID
        saided data = kith+tuid+saiddummy+span+limb
    span is Number instance encoding 2 byte int of number of MSbits in leaf limb
             always 256 == MaxSpan
    limb is Diger instance encoding of 256 bit branch path to leaf with MSbits
        always 256 == MaxSpan
        limb calculated on leaf info said using tree specific digest code so
        limb inhabits same hash space as all other parts of tree.
        Leaf info said may use different digest algo from tree wide digest algo.
        Because limb makes secure committment to leaf info there is no security
        need to store leaf info said per leaf. It may be stored in separate
        field map indexed by limb for convenience.
       """
LeafSaidage = namedtuple("LeafSaidage", "kith tuid said span limb")

"""Nodage Doc String
A Nodage instance holds the per node fields where values use the appropriate
encoding depending on context.
For computation each field value is a Matter instance that enables convenient
access to the corresponding raw value of each instance.
For compact in memory storage each field value is serialized as the corresponding
.qb2 value of each instance.
For archival (disk) storage the field values are serialized as the corresponding
.qb64 value of each instance

Nodage fields:
    span is Number instance encoding 2 byte int of number of MSbits in node limb
        min 0 for root to max of 255 = MaxSpan-1
    limb is Diger instance encoding the 256 bits of which the MS (big endian)
        span bits provide the child forks to node. Depth == limb span MSbits
    left is Noncer instance of left child's Saidage:
        node or leaf or empty (only root node children can be empty)
    right is Noncer instance of right child's Saidage:
        node or leaf or empty (only root node children can be empty)
"""
Nodage = namedtuple("Nodage", "span limb left right", defaults=(EmptyQb2, EmptyQb2))

"""Leafage Doc String
A Leafage instance holds the per leaf fields where values use the appropriate
encoding depending on context.
For computation each field value is a Matter instance that enables convenient
access to the corresponding raw value of each instance.
For compact in memory storage each field value is serialized as the corresponding
.qb2 value of each instance.
For archival (disk) storage the field values are serialized as the corresponding
.qb64 value of each instance

Leafage Fields:
    span is Number instance encoding 2 byte int of number of MSbits in leaf limb
             always 256 == MaxSpan
    limb is Diger instance encoding the 256 bits (big endian) of potential
        child forks to leaf. All 256 bits are meaningful but for any leaf attached
        to a given node only the MS node span+1 are used to address that leaf
        The limb digest is computed on leaf infos said which said is bound to
        actual leaf info. The info said algo may differ from the tree wide algo
        used to compute node and leaf saids.
"""
Leafage = namedtuple("Leafage", "span limb")

"""Partage Doc String
Partage is namedtuple of tree part (node or leaf) of form (said, part).
A Partage instance field values use the appropriate encoding depending on context.
For computation each field value is a Matter instance that enables convenient
access to the corresponding raw value of each instance.
For compact in memory storage each field value is serialized as the corresponding
.qb2 value of each instance.
For archival (disk) storage the field values are serialized as the corresponding
.qb64 value of each instance

Partage fields:
    said is Diger instance of said of full Saidage for part
    part is either a Nodage or Leafage instance as appropriate for part
"""
Partage = namedtuple("Partage", "said part")



class Siter:
    """Siter manages a SAIDed Info Tree (SIT)


    Attributes::
        tuider (Noncer): instance encoding crypto 16 byte4 tree unique identifier
                       this ensures separation of digests within each unique tree.
        code (str): qb64 digest code shared by all node/leaf SAIDs
        root (Partage: instance of root Partage as (root said, rootage)) where
                       values are matter instances:
                       said is Diger instance, part is Nodage instance whose
                           values are Matter instances
        nodes (dict): Nodage instances indexed by node said
        leaves (dict): Leafage instances indexed by leaf said
        infos (dict): leaf info saids as indexed by leaf limb

    ToDo: change .nodes, .leaves, and .infos to have virtual interface
          that supports either in-memory and disk based storage
    """
    Dummy = '#'  # default dummy for computing SAIDs
    Code = MtrDex.Blake3_256  # class default code for computing SAIDs

    @classmethod
    def saidify(cls, saidage, label='said', code=None):
        """Computes said of saidage and returns saidified copy of saidage where
        said field value given by label is replaced with computed said as saider.

        Returns::
            saidage (namedtuple): instance as saidified replacement of saidage

        Parameters::
            saidage (namedtuple): instance from which to compute and replace said
                                  field given by label
            label (str): field to hold said
            code (str|None): digest code for computing said. None means cls.Code


        Eventually when we have a Structor subclass with group code we can
        use a Structor instance to calculate the said
        """

        code = code if code is not None else cls.Code

        dqb64b = {l: v.qb64b for l, v in saidage._asdict().items()}  # get .qb64b of each field
        try:
            # create  dumied said field as bytes
            dqb64b[label] = (cls.Dummy * Noncer._fullSize(code)).encode()
        except KeyError as ex:
            raise ValueError(f"Invalid said field {label=}") from ex

        ser = b''.join(dqb64b.values())  # dummied ser
        saider = Noncer(ser=ser, code=code)
        if saider.code not  in DigDex:  # reforce strict so must be valid digest
            raise InvalidCodeError(f"Unsupported Digest code={saider.code}.")

        rkwa = dict()  # dict for namedtuple replace of said field with saider
        rkwa[label] = saider
        return saidage._replace(**rkwa)


    @staticmethod
    def extendLimbInt(limb, span=0, side=False):
        """Extends limb  of span using  bit value given by right and
        returns new limb extended by 1 bit.  Uses int values not Matter instances

        Returns:
            result (tuple): (limb, span) where:
                            limb is extended limb with span+1 MSbits. All other bits
                                masked to 0s.
                            span is span+1

        Parameters:
            limb (int): 256 bit limb path with span MSbits to be extended
            span (int): span of limb 0-255 MSbits
            side (bool): True means extend with 1 (right child bit)
                         False means extend with 0 (left child bit)

        Usage::
            given limber as Diger instance of limb
            given spanner as Number instance of span

            limb = Sider.extendLimbInt(limb=limber.num),
                                       span=spanner.num)

            or

            limb = Sider.extendLimbInt(limb=limber.num),
                                       span=spanner.num,
                                       right=True)

            limber = Diger(raw=limb.to_bytes(MaxSpanBytes))
            spanner = Number(num=spanner.num+1)
        """
        if span >= MaxSpan:
            raise ValueError(f"Invalid {span=} greater than MaxSpan")

        mask = ((1 << span) - 1)  # mask of 1s of length span
        limb = (limb >> (MaxSpan - span)) & mask
        limb = limb << 1  # extend with zero
        if side:
            limb |= 1  # make lsb 1
        span += 1
        return (limb << (MaxSpan - span), span)


    @staticmethod
    def extendLimb(limber, spanner, side=False):
        """Extends limber of span spanner with bit value given by left and
        returns tuple of (limber, spanner) where:
            limber extended by 1 bit and
            spanner incremented by 1.

        Returns:
            result (tuple): of form (limer, spanner) where:
                            limber is Diger instance of extended limb
                            spanner is Number instance of incremented span

        Parameters:
            limber (Diger): instance encoding 256 bit limb path with span MSbits
                            to be extended
            spanner (Number): instance encoding limb span MSbits [0..255]
            side (bool): True means extend with 1 (right child bit)
                         False means extend with 0 (left child bit)

        Usage::
            given limber as Diger instance of limb
            given spanner as Number instance of span

            limber, spanner = Sider.extendLimb(limber=limber, spanner=spanner)

            limber, spanner = Sider.extendLimb(limber=limber,
                                               spanner=spanner,
                                               right=True)
        """
        code = limber.code  # save to recreate
        limb = limber.num
        span = spanner.num
        limb, span = Siter.extendLimbInt(limb=limb, span=span, side=side)
        limber = Diger(raw=limb.to_bytes(MaxSpanBytes), code=code)
        spanner = Number(num=span)
        return (limber, spanner)


    @staticmethod
    def rightAtSpanInt(limb, span):
        """Returns which side of limb at span where:
        True is right and False is left
        Usually applied to leaf limbs so uses leaf convention:
        Convention MSb at span 1 and LSb at span 256.
        Minimum span allowed is 1 and maximum is 256.
        span is how many bits into limb either node or leaf.
        A leaf is always attached as a child of a parent node. The leaf child
        side is determined by bit position in leave limb that must be greater
        that span of parent node's span

        Returns:
            side (bool): False if bit at span is  0 (side is left)
                         True if bit at span is 1 (side is right)

        Parameters:
            limb (int): 256 bit int where MSbits are forks (0 left, 1 right)
            span (int): get bit at span where:
                            span = 1 is MSb of limb
                            span = 256 is LSb of limb
        """
        if span <= 0:
            raise ValueError(f"Invalid {span=} <= 0>")

        return True if (limb >> (MaxSpan - span) & 1) else False


    @staticmethod
    def rightAtSpan(limber, spanner):
        """Returns which side of limber at spanner where:
        True is right and False is left
        where limber and spanner are Matter primitives.
        Wrapper around Siter.rightAtSpanInt
        Convention MSb at span 1 and LSb at span 256.
        Minimum allowed span is 1 and maximum is 256.

        Returns:
            side (bool): False if bit at span is  0 (side is left)
                         True if bit at span is 1 (side is right)

        Parameters:
            limber (Diger): instance .num is 256 bit int where MSbits
                            are forks (0 left, 1 right)
            spanner (Number): instane .num is span where:
                         span = 1 is MSb of limb
                         span = 256 is LSb of limb
        """
        return Siter.rightAtSpanInt(limb=limber.num, span=spanner.num)


    @staticmethod
    def twigAtSpanInt(limb, span):
        """Returns right shifted masked limb with span MS bits in order
        to match limb prefixes (twigs). Values are ints.

        Returns:
            twig (int|None): right shifted masked limb with span MS bits.
                             None if root with empty twig at span = 0

        Parameters:
            limb (int): 256 bit int where MSbits are forks (0 left, 1 right)
            span (int): number of MS bits in limb to shift and mask where:
                            span = 1 is MSb of limb
                            span = 256 is LSb of limb
        """
        if span < 0:
            raise ValueError(f"Invalid {span=} <= 0>")
        elif span == 0:  # root so empty twig
            return None
        mask = ((1 << span) - 1)
        return ((limb >> (MaxSpan-span)) & mask)


    @staticmethod
    def twigAtSpan(limber, spanner):
        """Returns right shifted masked limb with span MS bits in order
        to match limb prefixes (twigs).
        Values are Matter instances
        Wrapper around Siter.twigAtSpanInt

        Returns:
            twigger (Diger): instance .num right shifted masked limb with
                             span MS bits.

        Parameters:
            limber (Diger): instance .num is 256 bit int where MSbits are forks
                            (0 left, 1 right)
            spanner (Number): instance .num  is number of MS bits in limb to
                              shift and mask where:
                                span = 1 is MSb of limb
                                span = 256 is LSb of limb
        """
        return Number(num=Siter.twigAtSpanInt(limb=limber.num, span=spanner.num))


    @staticmethod
    def fitLeafNodeInt(leaf, node, span):
        """Determines if node limb twig of size span is prefix of leaf limb
        i.e. leaf limb would fit at or below node twig on child branch of node
        Values are int

        Returns::
            fit (bool): True means leaf limb would fit on node. i.e. node twig
                            is prefix of leaf limb so same branch
                        False means leaf limb not fit on node i.e. node twig
                            is not prefix of leaf limb so not same branch
        Parameters::
            leaf (int): limb
            node (int): limb
            span (int): span of node limb used to get node twig.
        """
        return Siter.twigAtSpanInt(node, span) == Siter.twigAtSpanInt(leaf, span)


    @staticmethod
    def fitLeafNode(leafer, noder, spanner):
        """Determines if node limb twig of node of size spanner is prefix of leaf limb
        i.e. leaf limb would fit at or below node twig
        Parameters are Matter instances

        Returns::
            fit (bool): True means leaf limb would fit on node. i.e. node twig
                            is prefix of leaf limb so same branch
                        False means leaf limb not fit on node i.e. node twig
                            is not prefix of leaf limb so not same branch
        Parameters::
            leafer (Diger): limb
            noder (Diger): limb
            spanner (Number): span of node limb used to get node twig
        """
        return Siter.fitLeafNodeInt(leafer.num, noder.num, spanner.num)


    @staticmethod
    def sameLeafNodeSpan(leafer, noder, spanner):
        """Returns span of bits for which prefix for leaf and node limbs are the
        same.  Values are Matter instances

        Returns:
            samer (Number): instance span of prefix for which leaf and node
                            limbs are same
                        O when first bit differs. same is <= span of node

        Parameters:
            leafer (Number): instance limb of leaf with MaxSpan MSbits
            noder (Number): instance limb of node with span MSbits
            spanner (Number): instance span of node limb (max MaxSpan-1, min 0)
        """
        same = self.sameLeafNodeSpanInt(leaf=leafer.num, node=noder.num, span=spanner.num)
        return(Number(num=same))


    @staticmethod
    def forkSpanSwapInt(left, right):
        """Computes and returns tuple (span, swap) where:
        span is int of shallowest fork (bit position) where limbs differ
            (1 is shallest, 256 is deepest)
        swap is boolean True means left and right need to swap at fork
                            because left limb is 1 and right limb is 0 at fork
                        False means left and right do not need to swap at fork
                            because left limb is 0 and right limb is 1 at fork
        Values are ints

        Returns::
            fork (tuple): of form (span, swap) where:
                span is int of shallowest fork (bit position) where
                    limbs differ (1 is shallest, 256 is deepest)
                swap is boolean
                    True means left and right need to swap at fork
                        because left limb is 1 and right limb is 0 at fork
                    False means left and right do not need to swap at fork
                        because left limb is 0 and right limb is 1 at fork

        Parameters::
            left (int): 256 bit limb on left side
            right (int): 256 bit limb on right side
        """
        if left == right:
            raise ValueError(f"Bad pair left={right=}")
        for span in range(1, 256):
            leftbit = (left >> (MaxSpan - span)) & 1
            rightbit = (right >> (MaxSpan - span)) & 1
            if leftbit != rightbit:  # shallowest fork found at span
                swap = True if leftbit else False
                break

        return (span, swap)


    @staticmethod
    def forkSpanSwap(lefter, righter):
        """Computes and returns tuple (span, swap) where:
        span is int of shallowest fork (bit position) where limbs differ
            (1 is shallest, 256 is deepest)
        swap is boolean True means left and right need to swap at fork
                            because left limb is 1 and right limb is 0 at fork
                        False means left and right do not need to swap at fork
                            because left limb is 0 and right limb is 1 at fork
        Values are matter instances

        Returns::
            fork (tuple): of form (spanner, swap) where:
                spanner is Number of shallowest fork (bit position) where
                    limbs differ (1 is shallest, 256 is deepest)
                swap is boolean
                    True means left and right need to swap at fork
                        because left limb is 1 and right limb is 0 at fork
                    False means left and right do not need to swap at fork
                        because left limb is 0 and right limb is 1 at fork

        Parameters::
            lefter (Diger): instance of 256 bit limb on left side
            righter (Diger): instance of 256 bit limb on right side
        """
        span, swap = Siter.forkSpanSwapInt(lefter.num, righter.num)
        return (Number(num=span), swap)




    def __init__(self, tuid=None, code=MtrDex.Blake3_256, **kwa):
        """Initialize instance

        Parameters::
            tuid (str|bytes|None): qb64 or qb64b of 16 byte tree unique identifier.
                                   None means generate crypto strength value.
                                   Use Noncer to create from raw 16 bytes.
            code (str|bytes): tree wide digest code (qb64 or qb64b) for saids


        """
        self.tuider = Noncer(nonce=tuid)  # None generates crypto random value
        self.code = code if code is not None else self.Code
        self.nodes = dict()
        self.leaves = dict()
        self.infos = dict()


        # make and insert root node in .nodes
        # span is 0, limb is all zeros, left is empty, right is empty
        rootage = Nodage(span=Number(num=0),
                         limb=Diger(raw=bytes(MaxSpanBytes), code=self.code),
                         left=Noncer(nonce=""),
                         right=Noncer(nonce=""))
        self.root = Partage(self.sayNode(rootage), rootage)
        self.pinNode(saider=self.root.said, nodage=self.root.part)


    def sayNode(self, nodage):
        """Computes and returns said of node as Matter primitive where said is
        computed with a NodeSaidage derived from nodage supplemented with per
        tree and per part field values taken from self (Siter instance)
        To 'say' is to 'hash' or to 'digest' the node.

        Returns::
            saider (Diger): instance where said is computed from NodeSaidage
                            derived from nodage as supplemented with tree fields

        Parameters::
            nodage (Nodage): instance of nodage whose field values are Matter
                             instances
        """
        saidage = NodeSaidage(kith=Ilker(ilk=Kiths.node, strict=False),
                              tuid=self.tuider,
                              said=Noncer(nonce=""),
                              span=nodage.span,
                              limb=nodage.limb,
                              left=nodage.left,
                              right=nodage.right)
        saidage = self.saidify(saidage)
        return saidage.said


    def hasNode(self, saider):
        """Checks for node at saider in .nodes

        Abstract interface to .leaves storage of Nodage for each node indexed
        by is said. Interface uses Matter instances for said and Nodage field
        values that hide the underlying serialization used by the storage.

        For in memory use compact .qb2 values.
        For archival on disk use .qb64 values.

        Returns::
            result (bool): True if saider key in .nodes
                           False otherwise

        Parameters::
            saider (Diger): instance encoding said of Nodage
        """
        return (saider.qb2 in self.nodes)


    def putNode(self, saider, nodage):
        """Puts node given by nodage into .nodes at said given by .saider
        Put is idempotent. If node already exists put does not overwrite it.

        Abstract interface to .nodes storage of Nodage for each node indexed
        by is said. Interface uses Matter instances for said and Nodage field
        values that hide the underlying serialization used by the storage.

        For in memory use compact .qb2 values.
        For archival on disk use .qb64 values.

        Returns::
            result (bool): True if nodage added to .nodes
                           False if entry at saider said already exists do
                               does not overwrite

        Parameters::
            saider (Diger): instance encoding said of nodage
            nodage (Nodage): instance whose field values are Matter instances

        """
        if saider.qb2 in self.nodes:
            return False  # already in .nodes

        # convert to qb2 for compact storage
        nodage = Nodage(span=nodage.span.qb2,
                        limb = nodage.limb.qb2,
                        left=nodage.left.qb2,
                        right=nodage.right.qb2)
        self.nodes[saider.qb2] = nodage
        return True


    def pinNode(self, saider, nodage):
        """Pins node given by nodage into .nodes at said given by .saider
        Pin is not idempotent. If node already exists pin overwrites it.

        Abstract interface to .nodes storage of Nodage for each node indexed
        by is said. Interface uses Matter instances for said and Nodage field
        values that hide the underlying serialization used by the storage.

        For in memory use compact .qb2 values.
        For archival on disk use .qb64 values.

        Parameters::
            saider (Diger): instance encoding said of nodage
            nodage (Nodage): instance whose field values are Matter instances

        """
        # convert to qb2 for compact storage
        nodage = Nodage(span=nodage.span.qb2,
                        limb = nodage.limb.qb2,
                        left=nodage.left.qb2,
                        right=nodage.right.qb2)
        self.nodes[saider.qb2] = nodage


    def getNode(self, saider):
        """Gets node from .nodes at said given by saider.

        Abstract interface to .nodes storage of Nodage for each node indexed
        by is said. Interface uses Matter instances for said and Nodage field
        values that hide the underlying serialization used by the storage.

        For in memory use compact .qb2 values.
        For archival on disk use .qb64 values.

        Returns::
            nodage (Nodage|None): instance whose values are Matter instances.
                                  None when not found

        Parameters::
            saider (Diger): instance encoding said of nodage

        """
        if nodage := self.nodes.get(saider.qb2):
            # convert to Matter instances for computation
            nodage = Nodage(span=Number(qb2=nodage.span),
                            limb=Diger(qb2=nodage.limb),
                            left=Noncer(qb2=nodage.left),
                            right=Noncer(qb2=nodage.right))
        return nodage


    def isNode(self, saider):
        """Given said returns True if said belongs to node, False otherwise
        Checks for presence in .nodes and that 0 <= span < MaxSpan

        Returns::
            result (bool):  True means said given by saider corresponds to leaf
                            False otherwise
        """
        if (nodage := self.getNode(saider)) is not None:
            if 0 <= nodage.span.num < MaxSpan:
                return True
        return False


    def remNode(self, saider):
        """Removes node from .nodes at said given by saider.

        Abstract interface to .nodes storage of Nodage for each node indexed
        by is said. Interface uses Matter instances for said and Nodage field
        values that hide the underlying serialization used by the storage.

        For in memory use compact .qb2 values.
        For archival on disk use .qb64 values.

        Returns::
            result (bool): True if entry at saider in .nodes found and removed
                           False if no entry at saider in .nodes

        Parameters::
            saider (Diger): instance encoding said of nodage

        """
        try:
            del self.nodes[saider.qb2]
        except KeyError as ex:
            return False

        return True


    def sayLeaf(self, leafage):
        """Computes and returns said of leaf as Matter primitive where said is
        computed with a LeafSaidage derived from leafage supplemented with per
        tree and per part field values taken from self (Siter instance)
        To 'say' is to 'hash' or to 'digest' the leaf.

        Returns::
            saider (Diger): instance where said is computed from LeafSaidage
                            derived from leafage as supplemented with tree fields

        Parameters::
            leafage (Leafage): instance of leafage whose field values are Matter
                             instances
        """
        saidage = LeafSaidage(kith=Ilker(ilk=Kiths.leaf, strict=False),
                              tuid=self.tuider,
                              said=Noncer(nonce=""),
                              span=leafage.span,
                              limb=leafage.limb)
        saidage = self.saidify(saidage)
        return saidage.said


    def hasLeaf(self, saider):
        """Checks for leaf at saider in .leaves

        Abstract interface to .leaves storage of Leafage for each leaf indexed
        by is said. Interface uses Matter instances for said and Leafage field
        values that hide the underlying serialization used by the storage.

        For in memory use compact .qb2 values.
        For archival on disk use .qb64 values.

        Returns::
            result (bool): True if leafer key in .leaves
                           False otherwise

        Parameters::
            saider (Diger): instance encoding said of Leafage
        """
        return (saider.qb2 in self.leaves)


    def putLeaf(self, saider, leafage):
        """Puts leaf given by leafage into .leaves at said given by .saider
        Put is idempotent. If leaf already exists put does not overwrite it.

        Abstract interface to .leaves storage of Leafage for each leaf indexed
        by is said. Interface uses Matter instances for said and Leafage field
        values that hide the underlying serialization used by the storage.

        For in memory use compact .qb2 values.
        For archival on disk use .qb64 values.

        Returns::
            result (bool): True if leafage added to .leaves
                           False if entry at saider said already exists do
                               does not overwrite

        Parameters::
            saider (Diger): instance encoding said of leafage
            leafage (Leafage): instance whose field values are Matter instances

        """
        if saider.qb2 in self.leaves:
            return False  # already in .leaves

        # convert to qb2 for compact storage
        leafage = Leafage(span=leafage.span.qb2,
                        limb = leafage.limb.qb2)
        self.leaves[saider.qb2] = leafage
        return True


    def pinLeaf(self, saider, leafage):
        """Pins leaf given by leafage into .leaves at said given by .saider
        Pin is not idempotent. If leaf already exists pin overwrites it.

        Abstract interface to .leaves storage of Leafage for each leaf indexed
        by is said. Interface uses Matter instances for said and Leafage field
        values that hide the underlying serialization used by the storage.

        For in memory use compact .qb2 values.
        For archival on disk use .qb64 values.

        Parameters::
            saider (Diger): instance encoding said of leafage
            leafage (Leafage): instance whose field values are Matter instances

        """
        # convert to qb2 for compact storage
        leafage = Leafage(span=leafage.span.qb2,
                          limb = leafage.limb.qb2)
        self.leaves[saider.qb2] = leafage


    def getLeaf(self, saider):
        """Gets leaf from .leaves at said given by saider.

        Abstract interface to .leaves storage of Leafage for each leaf indexed
        by is said. Interface uses Matter instances for said and Leafage field
        values that hide the underlying serialization used by the storage.

        For in memory use compact .qb2 values.
        For archival on disk use .qb64 values.

        Returns::
            leafage (Leafage|None): instance whose values are Matter instances.
                                    None when not found

        Parameters::
            saider (Diger): instance encoding said of leafage

        """
        if leafage := self.leaves.get(saider.qb2):
            # convert to Matter instances for computation
            leafage = Leafage(span=Number(qb2=leafage.span),
                              limb=Diger(qb2=leafage.limb))
        return leafage


    def isLeaf(self, saider):
        """Given said returns True if said belongs to leaf, False otherwise
        Checks for presence in .leaves and that span is MaxSpan

        Returns::
            result (bool):  True means said given by saider corresponds to leaf
                            False otherwise
        """
        if (leafage := self.getLeaf(saider)) is not None:
            if leafage.span.num == MaxSpan:
                return True
        return False


    def remLeaf(self, saider):
        """Removes leaf from .leaves at said given by saider.

        Abstract interface to .leaves storage of Leafage for each leaf indexed
        by is said. Interface uses Matter instances for said and Leafage field
        values that hide the underlying serialization used by the storage.

        For in memory use compact .qb2 values.
        For archival on disk use .qb64 values.

        Returns::
            result (bool): True if entry at saider in .leaves found and removed
                           False if no entry at saider in .leaves

        Parameters::
            saider (Diger): instance encoding said of leafage

        """
        try:
            del self.leaves[saider.qb2]
        except KeyError as ex:
            return False

        return True


    def updateNode(self, node, childer, side=False):
        """Updage node said given new child said childer at side given by right
        remove old node entry in .nodes at old said and pin new node entry at
        new said.  Values are Matter instances

        Raises error if unsuccessful

        Returns::
            new (Partage):  instance (said, nodage) with Matter instance values
                        as new node with updated said and child part of nodage

        Parameters::
            node (Partage): instance old node to be update
            childer (Noncer): instance of new child said
            side (bool):  True means replace right child said
                           False means replace left child said
        """
        if not self.remNode(node.said):  # first remove old node
            raise ValueError(f"Attempt to remove missing node="
                             f"{node.said.qb64}")
        # now replace
        side = 'right' if side else 'left'
        kwa = dict()
        kwa[side] = childer
        nodage = node.part._replace(**kwa)
        saider = self.sayNode(nodage)  # update said of node
        self.pinNode(saider, nodage)  # update .nodes with replacement
        return Partage(saider, nodage)  # return new node


    def forkNode(self, node, left, right, side=False):
        """Attach new forking node to  side (right/left) of node where
        left and right are forking node's left and right children. The limb of
        forking node is set to shallowest common twig of left and right limbs.

        Parameters:
            node (Partage): instance (said, part) of node where:
                            said is Noncer instance of node said
                            part is Nodage instance with Matter instance values
            left (Partage): instance of left child for new forking node
                            (said, part) with Matter instance values.
                            part may be Nodage or Leafage instance
            right (Partage): instance of right child for new forking node
                            (said, part) with Matter instance values.
                            part may be Nodage or Leafage instance
            side (bool):  False means put forking node on left child of node
                          True means put forking node on right child of node

        Returns:
            newnode (Partage): instance (said, part) of updated node where:
                            said (Noncer): instance of new nodes said
                            part is Nodage instance with Matter instance values

        """
        # create new forking node of left and right with limb at shallowest
        # common span of limbs
        span, swap = self.forkSpanSwapInt(left.part.limb.num, right.part.limb.num)
        span = span - 1  # common span is 1 less than diff bit span
        # since common does not matter if we use left or right limb to get twig
        limb = self.twigAtSpanInt(left.part.limb.num, span) << MaxSpan - span
        if swap:  # swap left and right
            save = left
            left = right
            right = save

        # create nodage of new forking node
        nodage = Nodage(span=Number(num=span),
                        limb=Diger(num=limb),
                        left=left.said,
                        right=right.said)
        saider = self.sayNode(nodage)  # update said of forking node
        self.pinNode(saider, nodage)  # update .nodes with forking node
        return self.updateNode(node, saider, side=side)


    def forkNodeOld(self, node, lefter, righter, side=False):
        """Attach new forking node to  side (right/left) of node with where
        forking node's left child is lefter and right child is righter
        limb of forking node

        Parameters:
            node (Partage): instance (said, part) of node where:
                            said is Noncer instance of node said
                            part is Nodage instance with Matter instance values
            lefter (Noncer): instance of left child said for new forking node
            righter (Noncer): instance of right child said for new forking node
            side (bool):  False is left side
                          True is right side

        Returns:
            nodepartage (Partage): instance (said, part) where:
                            said is qb2 of node
                            part is Nodage instance with qb2 values
                            old and new provide left and right as appropriate

        """
        # create new forking node of lefter and righter
        # extend limb of node on side given by side
        limber, spanner = self.extendLimb(node.part.limb, node.part.span, side=side)
        # create nodage of new forking node
        nodage = Nodage(span=spanner, limb=limber, left=lefter, right=righter)
        saider = self.sayNode(nodage)  # update said of forking node
        self.pinNode(saider, nodage)  # update .nodes with forking node
        return self.updateNode(node, saider, side=side)

    def leafFromLimber(self, limber):
        """Create leaf to insert from limber. Computes leaf limb and said.

        Returns::
            leaf (Partage): instance (said, part) where:
                            said is Noncer instance generated from leafage
                            part is Leafage instance with Matter instance values

        Parameters::
            limber (Noncer): instance only per leaf unique value used to generate
                             leafage and then said of leaf
        """
        leafage = Leafage(span=Number(num=256), limb=limber)
        saider = self.sayLeaf(leafage)  # compute leaf said
        return Partage(said=saider, part=leafage)  # matter primitives


    def leafFromLeafer(self, leafer):
        """Create leaf to insert from leafer. Computes leaf limb and said.

        Returns::
            leaf (Partage): instance (said, part) where:
                            said is Noncer instance generated from leafage
                            part is Leafage instance with Matter instance values

        Parameters::
            leafer (Noncer): instance only per leaf unique value of said of info
                             used to generate limber which is then used to
                             generate leafage then used to generate said of leaf
        """
        limber = Noncer(ser=leafer.raw, code=self.code)  # limb for leaf
        return self.leafFromLimber(limber)


    def insert(self, leafer):
        """Insert leafer idempotently

        Returns::
            leaf (Partage|None)): of inserted leaf corresponding to leafer
                When successful insert Partage instance (said, part) where:
                        said is Noncer instance of leaf said
                        part is Leafage instance with Matter instance values
                Otherwise:  None

        Parameters::
            leafer (Noncer): instance encoding of leaf info said which said is
                            digest of actual leaf information. leafer may use
                            a different digest code from .code.
                            Thus a siter is compatible with all external leaf
                            info saids while ensuring for security reasons that
                            all its internal leaf limbs, leaf saids, and node saids
                            use the same digest algorithm give by .code.


        """
        # setup for ._insert
        leaf = self.leafFromLeafer(leafer)
        if self.hasLeaf(leaf.said):
            return None  # already inserted

        # start at root (values as matter primitives) raise error if ._insert fails
        try:
            self.root = self._insert(leaf, self.root)  # new root with inserted leaf
        except ValueError as ex:
            return None
        self.pinLeaf(leaf.said, leaf.part)  # add leaf
        self.infos[leaf.part.limb.qb64] = leafer.qb64  # add ref to leafer to infos
        return leaf



    def _insert(self, leaf, node):
        """Recursive inset of leafer starting at node. Descends tree until finds
        bottom node the recursively climbs back up tree up updating node saids
        as it climbs.  Values are Matter instances


        Returns::
            new (Partage): instance (said, part) of new updated node replacing
                           old node where recursive ._insert began where:
                           said is Noncer instance of node said
                           part is Nodage instance with Matter instance values

        Parameters::
            leaf (Partage): instance (said, part) of leaf to be inserted where:
                            said is leaf said Noncer instance
                            part is Leafage of leaf with Matter instance values

            node (Partage): instance of (said, part) as part of tree to
                            begin/resume recursive insert where:
                            said is node said Noncer instance
                            part is Nodage of node with Matter instance values


        Logic:
            leaf can only attach to child of node on side given by bit in leaf
            limb which bit is located below (greater than) the node span.
            This leaves room for one more nodes to interposed either above or
            below the node to which a leaf is attached. The key is that the
            limb of a given node is set by the deepest common span of its
            child leaves (node and/or leaf). This leaves gaps in the tree where
            virtual missing nodes with empty children would have been. We can
            call these ghost nodes. As long as the gaps between non-ghost nodes
            are stable the ghost nodes themselves do not need to be hashed/digested

            Becaause each node and leaf said is computed over its limb, there
            is no malleability in structure wrt the said (digest/hash) of a node
            or leaf. This prevents a collision attack from missing virtual
            empty nodes. As new leaves are added the new node
            fork created to accomodate the leaf may interpose either above or
            below an existing node. A given node's limb once set remains, but its
            children may change as new leafs and nodes to accomodate the leaves
            are added. The rules for forking nodes are designed to ensure the
            essential property that that same set of nodes no matter the order of
            insertion results in the same root said (digest/hash)

            When a new leaf causes a new fork to be interposed above an existing
            node, the existing node's said does not change. This means saids
            lower in that subtree remain stable. So the only hashes (saids) that
            change are above it in its given branch.  The limb of the new node
            is always set to the deepest common span of its children. This
            leaves a stable gap for any missing ghost nodes above it in the tree.


            When a new leaf causes a new fork to be interposed below  existing
            node then the existing nodes above it must change their saids but
            the nodes below the new node do not. In order for a fork to be
            inserted below a node, the leaf must itself fit below that node.
            The new node always has a limb value that is set to the deepest
            common span of its children. This creates a stable gap for the
            missing ghost nodes.

            Creating stable gaps for missing ghost nodes supports the required
            property of a sparse Merkle tree, that is, that the order of insertion
            of its leaves does not change the final node structure.
            A leaf can only go in one place.

            The act of fixing node limbs, fixes their relative place in the tree.
            The infil above protects the tructure below so new leaves go to the
            same place in the tree no matter the order of insertion.

            ToDo: XXX need new function sameLimbSpan between node and leaf since node
            and leaf may be common all 256. since common comparison is only valid
            to node span not beyond and swap not apply when common all the way.

            forkSpanSwap does not work when node and leaf same all the way down.

        """
        # Walk leaf down appropriate node child branch.
        # assumes node limb is prefix of leaf limb. leaf fits below node.
        # Root limb is empty so always prefix of any leaf limb. leaf fits below root.
        # figure out which side of node, leaf must go
        if self.rightAtSpanInt(leaf.part.limb.num, node.part.span.num + 1):  # go right
            side = True  # set side to right
            # get child on right
            childer = node.part.right   # empty or leaf saider or node saider
        else:  # go left
            side = False  # set side to left
            # get child on left
            childer = node.part.left  # empty or leaf saider or node saider

        if not childer.nonce:  # child is empty (should only happen at root node)
            # attach leaf to side of node, update node and return
            if node.part.span.num != 0:  # not root
                raise ValueError(f"Invalid node={node.said.qb64}, not root "
                                 f"but empty child on {side=}")
            # remove, replace, and return updated node with new child on side
            return self.updateNode(node, leaf.said, side=side)

        if (leafage := self.getLeaf(childer)) is not None:  # child is leaf
            # fork node on side.  set limb of new node to common span before
            # shallowest diff and put leafs on side at diff bit at common span +1
            # update node and return
            child = Partage(childer, leafage)  # make child
            # need to updage forkNode to use common limb not just extension
            return self.forkNode(node, left=leaf, right=child, side=side)


        if (nodage := self.getNode(childer)) is not None:  # child is node
            #  walkdown means span of limb of node is longer than common span
            #  between node and leaf
            # if can walk down on side:
            #          recurse with with child node on side
            # else: cannot walk down past child node:
            #          fork  between node and its child node on side.
            #                above child node and below node.
            #          fork at shallowest span diff of leaf and child node on side
            #          child node should stay on same side of new fork node as it
            #          was on node and leaf should go on other side of new fork node
            #          check if swap says otherwise
            #          update node and return
            #
            child = Partage(childer, nodage)  # make child

            if not self.fitLeafNode(leafer=leaf.part.limb,
                                    noder=child.part.limb,
                                    spanner=child.part.span):  # cannot walk down
                # leaf cannot recurese down child node path
                return self.forkNode(node, left=leaf, right=child, side=side)

            # can recurse down child so recurse
            child = self._insert(leaf=leaf, node=child)  # recursion updates child
            # remove, replace, and return updated node with new child on side
            return self.updateNode(node, child.said, side=side) # right

        raise ValueError(f"Should never get here")


    def trace(self):
        """Returns list of leaves in depth first search order.
        Children firt left then right.

        Each entry is string with leaf limb at node twig MSb)
        """
        leaves = []  # mutable will fill in as it traces
        self._trace(self.root, leaves)

        return leaves


    def _trace(self, node, leaves):
        """Recursive descent depth first trace starting at node to find attached
        leaves where chidren are searched first left then right

        Each entry is tuple of (leaf limb, node limb MSb)
        """
        limb = node.part.limb.num
        span = node.part.span.num
        if (twig := self.twigAtSpanInt(limb, span)) is not None:
            showtwig = f"{twig:0{span}b}"
        else:
            showtwig = f"root"

        lefter = node.part.left
        if not lefter.nonce:  # left leaf empty
            leaves.append(f"left: empty @ {showtwig}")
        elif (leafage := self.getLeaf(lefter)) is not None: # left leaf

            leaves.append(f"left: {(leafage.limb.num>>248):08b} @ {showtwig}")
        else: #left node so recurse
            nodage = self.getNode(lefter)
            self._trace(Partage(lefter, nodage), leaves)

        righter = node.part.right
        if not righter.nonce:  # right leaf empty
            leaves.append(f"right: empty @ {showtwig}")
        elif (leafage := self.getLeaf(righter)) is not None: # right leaf
            leaves.append(f"right: {(leafage.limb.num>>248):08b} @ {showtwig}")
        else: #right node so recurse
            nodage = self.getNode(righter)
            self._trace(Partage(righter, nodage), leaves)




