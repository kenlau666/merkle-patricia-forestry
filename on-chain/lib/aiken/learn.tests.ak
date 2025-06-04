use aiken/builtin.{blake2b_256, index_bytearray, write_bits}
use aiken/collection/list
use aiken/fuzz.{int}
use aiken/merkle_patricia_forestry.{
  Branch, Fork, Leaf, MerklePatriciaForestry, Neighbor, Proof, ProofStep,
} as mpf
use aiken/merkle_patricia_forestry/helpers.{combine, nibbles, suffix}
use aiken/merkle_patricia_forestry/merkling.{null_hash}
use aiken/primitive/bytearray

const guava = "guava[uid: 344]"

const kiwi = "kiwi[uid: 0]"

pub type Tree {
  Branch { nibble: ByteArray, nodes: List<Pair<Int, Tree>> }
  Leaf { key: ByteArray, value: ByteArray }
}

test learn() {
  let tree: Tree =
    Branch {
      nibble: #"05",
      nodes: [
        Pair(
          0,
          Branch {
            nibble: #"07",
            nodes: [
              Pair(
                6,
                Leaf {
                  key: #"5076d8ab234597ab6a35c03c805381bbc016025b36ff1f7df9c5009e1a8b73ef",
                  value: "🤷",
                },
              ),
              Pair(
                12,
                Leaf {
                  key: #"507c58473af4b3e5b24e65481294b0772ed6a7dd793937c6c90179960d154a22",
                  value: "🥝",
                },
              ),
            ],
          },
        ),
        Pair(
          10,
          Leaf {
            key: #"5a522f84bcda4bebb725d5f2b92af615b57cc1777bb0d8b2c6c18c3e3e6520cd",
            value: "🤷",
          },
        ),
      ],
    }

  compute_tree_hash(tree, #"") == #"83a5c96888616bc2be9e65b6fab3673d57a862467f89ac14294aec2f2bc73ae3"
}

fn compute_tree_hash(tree: Tree, prefix_nibbles: ByteArray) -> ByteArray {
  when tree is {
    Branch { nibble, nodes } -> {
      // Maybe we can do something without reversing the list?
      let child_hashes =
        list.reverse(
          build_child_hashes(
            [],
            nodes,
            0,
            bytearray.concat(prefix_nibbles, nibble),
          ),
        )
      let merkle_root = build_merkle_hash(child_hashes)
      compute_branch_hash(nibble, merkle_root)
    }
    Leaf { key, value } -> {
      let cursor = bytearray.length(prefix_nibbles)
      let key_nibbles = nibbles(key, 0, cursor)
      if key_nibbles == prefix_nibbles {
        compute_leaf_hash(key, value, cursor)
      } else {
        trace @"key_nibbles": key_nibbles
        trace @"prefix_nibbles": prefix_nibbles
        fail @"invalid tree, prefix does not match key"
      }
    }
  }
}

// This operation is going to be inefficient since we're pushing to the end of the list repeatedly. 
// TODO: optimize
fn build_merkle_hash(child_hashes: List<ByteArray>) -> ByteArray {
  when child_hashes is {
    [x] -> x
    [x, y, ..xs] -> build_merkle_hash(list.concat(xs, [combine(x, y)]))
    _ -> fail @"invalid child hashes, must be a non-empty list"
  }
}

fn build_child_hashes(
  child_hashes: List<ByteArray>,
  nodes: List<Pair<Int, Tree>>,
  cursor: Int,
  prefix_nibbles: ByteArray,
) -> List<ByteArray> {
  if cursor == 16 {
    child_hashes
  } else {
    let maybe_node_head = list.head(nodes)
    when maybe_node_head is {
      None ->
        // If we reach the end of the nodes list, we fill the remaining child hashes with null_hash
        build_child_hashes(
          list.push(child_hashes, null_hash),
          nodes,
          cursor + 1,
          prefix_nibbles,
        )
      Some(node_head) -> {
        // If we have a node, we check its index and compute the hash accordingly
        let node_index = node_head.1st
        if cursor > node_index {
          fail @"invalid tree, children must be sorted by index"
        } else {
          expect Some(tail_nodes) = list.tail(nodes)
          if cursor == node_index {
            let new_prefix =
              bytearray.concat(
                prefix_nibbles,
                bytearray.from_int_big_endian(cursor, 1),
              )
            build_child_hashes(
              list.push(
                child_hashes,
                compute_tree_hash(node_head.2nd, new_prefix),
              ),
              tail_nodes,
              cursor + 1,
              prefix_nibbles,
            )
          } else {
            build_child_hashes(
              list.push(child_hashes, null_hash),
              nodes,
              cursor + 1,
              prefix_nibbles,
            )
          }
        }
      }
    }
  }
}

fn compute_leaf_hash(key: ByteArray, value: ByteArray, cursor: Int) -> ByteArray {
  combine(suffix(key, cursor), blake2b_256(value))
}

fn compute_branch_hash(nibble: ByteArray, root: ByteArray) -> ByteArray {
  combine(nibble, root)
}
