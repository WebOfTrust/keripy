# -*- encoding: utf-8 -*-
"""
keri.sit.parting module

Package shared part definitions to avoid circular imports


"""
from collections import namedtuple

from ..core import Noncer

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


