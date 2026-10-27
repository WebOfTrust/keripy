# -*- encoding: utf-8 -*-
"""
keri.smt.branching module

OC-SMT  core functional support


(Zero is a special unique value that should not correspond to a real leaf's value.
(Can we use None in python) In Ethereum world they use the string `0x00000...`

The docs for merkle trees get this mixed up. Sometimes when they say 0 they
mean literally a 0 bit but other times they mean a special hash value.

key in sparse merkle tree is the concatenation of the path. A key of 256 bits
is a left-right forking path down tree.
If a bit position is 0 go left else 1 go right
There are 2^256 keys  value (0...0) to (1...1)

In a binary Merkle tree, a 0 typically represents the left child branch and
a 1 represents the right child branch when navigating from the root down toward a leaf.
• 0 = Left Branch: Moving down to the left child node in the pair.
• 1 = Right Branch: Moving down to the right child node in the pair.

How Branch Direction Works

• Path Navigation: When walking from the root to a leaf, each step in the path
or Merkle proof is designated by a bit (such as 0 or 1) so the verifier knows
whether the sibling hash should be concatenated on the left or on the right
during hash reconstruction.
• Concatenation Order: Parent hashes are computed as H(left || right),
meaning the position (left vs. right) dictates the sequence in which hashes are joined together.
• Bitwise Indexing: In sparse or binary-indexed structures, binary path digits
correspond directly to choosing the left (0) or right (1) branch at each depth level of the tree.


Nervos
Optimization 1: Zero-value optimized hash function
We define the node merging function as following:
if L == 0, return R
if R == 0, return L
otherwise return sha256(L, R)

With optimization 1, we do not need the pre-calculated hash-set.
For a default SMT, all the intermediate nodes are zero values.
Thus, we only need to calculate the hash for non-zero nodes and return zero
for the default nodes.



There’s only one issue that remains. The optimized hash function produces
the same value from different key-value pairs, for example:
merge(N, 0) == merge(0, N).
This behavior opens a weak point for the SMT. An attacker may construct a
collision of merkle root from a faked key-value map.

To fix this, we use the result of hash(key | value) as a leaf’s hash.
For example:
merge(N, leaf_hash(N, 0)) != merge(0, leaf_hash(0, N))
because the leaf_hash(N, 0) is never equals to leaf_hash(0, N) if N != 0,
the attacker can’t construct a collision attacking.

Additionally, we store leaf_hash -> value in a map to keep the reference
to the original value.

We can prove the security of this construction.

Since the key is included in the leaf’s hash, and key is unique in SMT,
no matter what the value is, the leaf_hash(key, value) is unique.
Each node is either merged by two different hashes or merged by a hash with
a zero-value. We already knew that all leaves have a unique hash, so their
parent nodes also have a unique hash, and so on.
The parent of these parent nodes also has a unique hash until the root of the tree.
We got zero value merkle root if the tree is empty.
Otherwise, the root is merged from its two children nodes. Any changes in the
leaves will also change the root hash.
So we believe this construction is security because we can’t construct
a collision of merkle root.


Optimization 2: abstract storage mechanics

In the classic construction of SMT: We store a branch node with its two children
as
Node {left, right}.

We have implemented branch node as the following data structure:

pub struct BranchNode
{
    pub left: MergeValue,
    pub right: MergeValue,
}
When left and right are both zero, it's not needed to store this zero node.

We still face problem: too many branch nodes in real world.
Assuming we have only one leaf node in SMT, there are still 255 branch nodes.
They are all ancestors of the only leaf node.
The amount of branch nodes can be easily reached to millions.
When the leaf nodes grows to above 10k, it can consume a lot of memory.
We realize that the databases or kv-store will be used in SMT proof.
Therefore, we introduce a abstracted layer of storage mechanics, trait Store as following:

/// Trait for customize backend storage
pub trait Store<V>
{
    fn get_branch(&self, branch_key: &BranchKey) -> Result<Option<BranchNode>, Error>;
    fn get_leaf(&self, leaf_key: &H256) -> Result<Option<V>, Error>;
    fn insert_branch(&mut self, node_key: BranchKey, branch: BranchNode) -> Result<(), Error>;
    fn insert_leaf(&mut self, leaf_key: H256, leaf: V) -> Result<(), Error>;
    fn remove_branch(&mut self, node_key: &BranchKey) -> Result<(), Error>;
    fn remove_leaf(&mut self, leaf_key: &H256) -> Result<(), Error>;
}

If branch nodes are not many, we can put them all in memory.
By default, we have such DefaultStore:

pub struct DefaultStore<V>
{
    branches_map: Map<BranchKey, BranchNode>,
    leaves_map: Map<H256, V>,
}

If branch nodes are too many, it's better to implement a database backend.
We suggest RocksDB: an embedded persistent key-value store for fast storage.
Here is an example of RocksDB backend implementation.
https://github.com/quake/smt-rocksdb-store

This store mechanics is only used in making SMT proof.
It doesn't affect on-chain SMT verification which is still very fast and memory-efficient.

Optimization 3: Shortcut nodes

We can optimize the storage space and performance by using shortcut nodes.
A shortcut is a node that has only one leaf node, it can be merged with its parent node.
The shortcut node is only used in the storage, it doesn't affect the verification process.
We implement it as following algorithm: Aergo Trie.
https://github.com/aergoio/aergo/tree/master/pkg/trie
This algorithm is enabled by trie feature, which is disabled by default.



Rust code

fn common_height(key1, key2)
{
    for i in 255..0
    {
        if key1.get_bit(i) != key2.get_bit(i)
        {
            // common height
            return i;
        }
    }
    return 0;
}

// get children at height
// return value is (left, right)
fn children(branch_node, height)
{
    let is_rhs = branch_node.key.get_bit(height);
    if is_rhs
    {
        return (branch_node.sibling, branch_node.node)

    }
    else
    {
        return (branch_node.node, branch_node.sibling)
    }
}

fn get(key)
{

    let node = root;

    // path order by height

    let path = BTreeMap::new();

    loop
    {
        let branch_node = match map.get(node)
        {
            Some(b) => b,
            None => break,
        }
        // common height may be lower than node.fork_height
        let height = max(common_height(key, node.key), node.fork_height);
        if height > node.fork_height
        {
            // node is sibling, end search
            path.push(heignt, node);
            break;
        }

        // node is parent
        // extract children position from branch
        let (left, right) = children(branch_node, height);

        // extract key positon
        let is_right = key.get_bit(height);
        if is_right
        {
            path.push(height, left);
            node = right;
        }
        else
        {
            path.push(height, right);
            node = left;
        }
    }
    return self.leaves[node];
}

use sparse_merkle_tree::
{
    blake2b::Blake2bHasher, default_store::DefaultStore,
    error::Error, MerkleProof,
    SparseMerkleTree, traits::Value, H256
};
use blake2b_rs::{Blake2b, Blake2bBuilder};

// define SMT
type SMT = SparseMerkleTree<Blake2bHasher, Word, DefaultStore<Word>>;

// define SMT value
#[derive(Default, Clone)]
pub struct Word(String);
impl Value for Word {
   fn to_h256(&self) -> H256
   {
       if self.0.is_empty()
       {
           return H256::zero();
       }
       let mut buf = [0u8; 32];
       let mut hasher = new_blake2b();
       hasher.update(self.0.as_bytes());
       hasher.finalize(&mut buf);
       buf.into()
   }
   fn zero() -> Self
   {
       Default::default()
   }
}

// helper function
fn new_blake2b() -> Blake2b
{
    Blake2bBuilder::new(32).personal(b"SMT").build()
}

fn construct_smt()
{
    let mut tree = SMT::default();
    for (i, word) in "The quick brown fox jumps over the lazy dog"
        .split_whitespace()
        .enumerate()
    {
        let key: H256 =
        {
            let mut buf = [0u8; 32];
            let mut hasher = new_blake2b();
            hasher.update(&(i as u32).to_le_bytes());
            hasher.finalize(&mut buf);
            buf.into()
        };
        let value = Word(word.to_string());
        // insert key value into tree
        tree.update(key, value).expect("update");
    }


    println!("SMT root is {:?} ", tree.root());
}

"""

