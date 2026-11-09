# Design of SIT SAIDed Info Tree

## Introduction

Maximally shallow balanced SAIDed Info Tree (SIT) where as verifiable Map where
the stucture metadata of each part of the tree (namely the part's path plus tree
metadata) is included in each part's hash.

This structure of digesting data and using that digest as a content addressable
identifier that is included with the digested data is exactly the SAID approch.

Thus we generalize the data storage as a SAIDed Information Tree or SIT.

Tree metadata stored once per tree but digested with each part includes:
- a universally unique tree identifier TUID  as a salty nonce
- a version of the tree
- the type of digest algorithm used to create the SAIDs for each node and leaf.

For compactness the structure metadata digests in each node and leaf in the
SIT uses the same digest type but any SAID can be anchored in a leaf.
Each leaf's data hash SAID digest type is  individually encoded.
This approach balances compactness with versatility as a data map.

Part data stored with each part (node or leaf) includes:
- height of part
- path of part
- children SAIDs if node part
- data SAID if leaf part


The height, `h` of a node indicates the height of the node in the tree.
The root node is at height `h=256`. The depth of a node is at `d = 256 - h`
Therefore the root node'depth is at `d=0`.
The height of a leaf is always zero no matter the height of which node it is
attached to. But the depth of a leaf is always one greater than the depth of
the node to which that leaf is attached, `d = nh  + 1` where `nh` is the
node height of the node to which the leaf is attached.

A path is encoded as a 32 byte, 256 bit number.
A 0 in a bit position is a left child and a 1 in a bit position is a right child.

For node paths, the number of significant bits aligned to the left (big endian)
is given by the height of the node. The other bits to the right are zeroed.
The MSb in a node path corresponds the path of a child attached
to a node at height 256 and  the LSb in the corresponds to the path of a child
attached to a node at its height. The minimum height of a node is 1. Only leaves
have height 0.

A leaf path is always of length 256, all bits matter. Each leaf is attached
to a node as a child where the node path is a prefix to the leaf path.


The path of a node is always its location in the tree. The root node has
a path length of zero. Path length is equal to `pl = 256 - h`.
Therefore the path length of a node is equal to its depth.
The path length of a leaf is always 256 because a leaf's height is always 0.

The SAID of a node is derived from the digest of its tree metadata,
height, path, and the SAIDs  of its two children.
The path of a leaf is derived from its SAID. Its SAID is derived from its
tree metadata, its height, and the SAID of its leaf data.

Each child of the root node may be another node, a leaf, or empty. The root node
is special because it may have zero, one or two empty children. All other nodes
(not the root) always have two non-empty children. Therefore we only need two
special SAIDs, one each for an empty left child and empty right child of the
root node.
Each child of non-root node always has two children. Each child may be another
non-root node or a leaf. A non-root node could have two leaf, two nodes, or one
node and one leaf as children.

The tree is automatically rebalanced each time a leaf is inserted.
Consequently, an already existing leaf may be forced to move as the result
of the insertion of a new leaf. Similarly,  with the exception of the case where
the root not has one or more empty children, a new node must be inserted
to accommodate a new leaf.

Once a node has been inserted it does not move within the tree (its height and
path i.e. its location in the tree stays the same). But anytime one or both
of its children changes then its SAID changes which may mean its storage location
in memory or on disk may change.

The tree grows from the root down.

```
node SAIDed data  (+ is concatenation operator)

TUID + Version + digestType + height + path + leftChildSAID + rightChildSAID

node data including its SAID

nodeSAID + TUID + Version + digestType + height + path + leftChildSAID + rightChildSAID

```

```
leaf SAIDed data  (+ is concatenation operator)

TUID + Version + digestType + height + leafDataSAID

leaf data including its SAID

leafSAID + TUID + Version + digestType + height + leafDataSAID

```

The data elements for each node and leaf are serialized using CESR. This enables
a tree or parts of a tree to be streamed in a CESR stream in either compact
CESR binary or readable text mode. CESR streams can attached to KERI
messages, or stored in a database. Each set of data elements uses a special
group code when included in a CESR stream. Each element (with the exception
of the version and digest type) uses a CESR primitive code appropriate to the
element type. The digest type is included as an extension of the version element.



## Empty Child Merging and Tree Size

The maximum path length determines the maximum number of leafs and hence nodes
in the tree. The optimization of using a balanced tree means that nodes are only
added as needed to accomodate the number of leafs. All nodes but the root node
have two children. Thus the tree grows down from the root and is maximally shallow
for its given set of leaves.

To elaborate the tree only adds nodes as needed to fork to non-empy leafs.
A SIT therefore  never has more nodes than the minimum needed
to store its leaves. If the leaf paths are uniformly distributed then the
tree will be well balanced and maximally shallow.

Sparse Merkle Tree algorithms that store nodes with an empty child
end up with average tree depths greater than` Log2(L)` where `L` is the number of
non-empty leaves.


## Security

Because node paths are derived from cryptographic strength hashes of the leaves,
the distribution of path segments is statistically uniform.
The average path length of a node is a function the statistically approximate
uniform distribution that results from a cryptographic strength digest.
Although the worst case for depth is always the maximum path length, using
the digest to generate the path and only storing forking nodes with non-empty
children means that on average the leaf depth is close to minimum of
`Log2(L)` where `L` is the number of leaves.

To restate, the principal advantage of a SIT comes from the fact that it is
constructed such that the averge depth of the leaves is close to `log2(L)`
where `L` is the number of non-empty leaves.

A SIT generalizes and simplifies the various security, storage, access and
proofing mechanisms implemented in the different varieties of optimized compact
sparse merkle trees.

Fundamentally from a security perspective, including each node's structure in
its hash (digest), especially its height and path, ensures that the nodes of
a given tree cannot be rearranged to result in different tree but with the
same root hash (digest).

This forces an attacker at the very least to perform a successful
collision attack on at least one or more hashes.

Using full cryptographic strength hashes makes any such successful collision attack
computationally infeasible.


Open question does order of insertion of a set of leaves matter to the root digest
Or does the rebalancing insure that any order of insertion of a set of leafs
always results in the same root digest?

Open question, on average how many leaf moves are needed to rebalance on each
new leaf insertion (hopefully 1 on average)

### Trade Space

A SIT makes some trade-offs vis-a-vis other sparsed merkle tree like algorithms.
The primary trade-off is that each node in the tree must store its structure
as meta-data in addition to the hashes (SAIDs) of its two children.

The node structure metadata that is unique for each node is the path.
The tree metadata is common to the whole tree and does not need to be stored
with each node.

Given the maximum leaf path length is the size of a cryptographic digest for
content addressable leaves then the per node storage is increased by roughly 50%
over a tree that only stores its two children hashes.  (3 hash equivalents
versus 2 hash equivalents per node.

The number of nodes in a binary tree is given by,
`N = 2^(D) - 1``
where `N` is the number of nodes and `D` is the average depth of the binary tree.

Therefore increasing the average tree depth by 1  doubles the number of
nodes `N`. Likewise decreasing the average depth of a binary tree by 1 halves the
number of nodes  `N`.

Consequently a tree design the reduces the average depth by 1 at the cost of a
100% increase in per node storage requirements would net out a zero increase in
total storage required.
in average depth of 1 results in a net zero difference in total storage required.

Let the variable `N` represent the number of nodes.
Let the variable `S` readssent the per-node storage required.
Let the variable `T` represent the total storage required

We have
`T = N * S`
So if we design a new tree algorithm where the new per node storage
`S1 = 1.5 * S` (50% increase)
but the new number of nodes is
`N1 = N/2 = 0.5 * N`
then the new total storage
`T1 = N1 * S1 = 1.5* S * 0.5 * N = (1.5)*(0.5)* N * S = 0.75* M * S = 3/4(N*S)`
or a 25% improvement.

To elaborate, we can double the per node storage if we decrease the average
depth by one and not incur a storage penalty. This gives us a per-node storage
budget target for optimizing the tree using structure meta-data.

In addition, reducing the average tree depth also minimizes the computation
requirements for inclusion and exclusion proofs which are always on the order
of the actual number of nodes on the branch to a given leaf
(to proof or disproof its membership in the tree)

So a tree that approaches the minimum of `Log2(L)` for the tree depth for non-empty
leaves `L` also optimizes computational performance for the number of reads to
generate a proof and the number of operations to verify a proof.

The trade-off is that using stucture metadata logic to rebalance the nodes
increases to the overhead to insert or delete a leaf from the tree.
But the insertion or deletion of a leaf is rare compared to the number of
times that that leaf must be read and verified. Indeed, for many applications
for a given tree,  the ratio of read/verify operations to insertion/deletion
operations might be  on the order of thousands to millions.
So overall performance is maximized by minimizing average leaf depth.

