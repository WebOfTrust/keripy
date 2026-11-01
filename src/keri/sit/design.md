# Design of SIT SAIDed Info Tree

## Introduction

Maximally shallow SAIDed Info Tree (SIT) where as verifiable Map where the
stucture metadata of each part of the tree (namely the part's path plus tree
metadata) is included in each part's hash.

The path is derived from a SAID of each part and leaf parts include the SAID
of the data bound to that leaf. Tree metadata includes a unique tree identifier
as a salty nonce, a version, and the type of digest algorithm used to create the
hashes for each node and leaf. Node hashes include the hashes (digests) of their
children. Leaf hashes in the the SAIDs of the data bound to the leaf.

This structure of digesting data and using that digest as a content addressable
identifier that is included with the digested data is exactly the SAID approch.

Thus we generalize the data storage as a SAIDed Information Tree or SIT.

## Empty Child Merging and Tree Size

The maximum path length determines the maximum number of leafs and hence nodes
in the tree. The optimization that nodes with empty children are merged up common
paths to minimize the number of nodes needed to store a given set of leaves.
Effectively merging means the tree grows down from the root. It only adds nodes
as needed to fork to non-empy leafs. A node with an empty child is always
merged up to its first uncommon parent (this is similar to how the
Nervos SMT works). A SIT therefore  never has more nodes than the minimum needed
to store its leaves with non-common path segments.

Sparse Merkle Tree algorithms that do not merge nodes with an empty child
end up with average tree depths greater than Log2(N) where N is the number of
non-empty leaves.


## Security

Because paths are derived from cryptographic strength hashes of the leaves, the
distribution of path segments is statistically uniform. The average path length
is a function the statistically approximate uniform distribution that
results from a cryptographic strength digest. Although the worst case for depth
is always the maximum path length, using the digest to generate the path and
only storing forking nodes with non-empty children means that on average the leaf
depth is close to Log2(N) where N is the number of leaves.

To restate, the principal advantage of a SIT comes from the fact that it is
constructed such that the averge depth of the leaves is close to log2(N)
where N is the number of non-empty leaves.

A SIT generalizes and simplifies the various security, storage, access and
proofing mechanisms implemented in the different varieties of optimized compact
sparse merkle trees.

Fundamentally from a security perspective, including each part's structure in
its hash (digest), especially its path, ensures that the parts of a given tree
cannot be rearranged to result in different tree but with the same root hash (digest).

This forces an attacker at the very least to perform a successful
collision attack on at least one or more hashes. Using full cryptographic strength
hashes makes any successful collision attack computationally infeasible.


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
``M = 2^(D) - 1``
where M is the number of nodes and D is the depth of the binary tree.

Therefore increasing the average tree depth by 1  doubles the number of
nodes M. Likewise decreasing the average depth of a binary tree by 1 halves the
number of nodes.

Consequently a tree design the reduces the average depth by 1 at the cost of a
100% increase in per node storage requirements would net out a zero increase in
total storage required.
in average depth of 1 results in a net zero difference in total storage required.

Let the variable M represent the number of nodes.
Let the variable S readssent the per-node storage required.
Let the variable T represent the total storage required

We have
`T = M * S`
So if we design a new tree algorithm where the new per node storage
`S1 = 1.5 * S ` (50% increase)
but the new number of nodes is
`M1 = M/2 = 0.5 * M`
then the new total storage
`T1 = M1 * S1 = 1.5* S * 0.5 * M = (1.5)*(0.5)* M * S = 0.75* M * S = 3/4(M*S)`
or a $25% improvement.

To elaborate, we can double the per node storage if we decrease the average
depth by one and not incur a storage penalty. This gives us a per-node storage
budget target for optimizing the tree using structure meta-data.

In addition, reducing the average tree depth also minimizes the computation
requirements for inclusion and exclusion proofs which are always on the order
of the actual number of nodes on the branch to a given leaf
(to proof or disproof its membership in the tree)

So a tree that approaches the minimum of Log2(N) for the tree depth for non-empty
leaves also optimizes computational performance for the number of reads to
generate a proof and the number of operations to verify a proof.

The trade-off is that using stucture metadata logic to compute the merged nodes
increased to the overhead to add or remove a leaf from the tree.
But the addition and subtraction of a leaf is rare compared to the number of
times that that leaf must be read and verified. Indeed, for many applications
for a given tree,  the ratio of read/verify operations to addition/deletion
operations might be  on the order of thousands to millions.
So overall performance is maximized by minimizing average leaf depth.

