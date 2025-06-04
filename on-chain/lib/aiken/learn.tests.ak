use aiken/builtin.{blake2b_256, index_bytearray, write_bits}
use aiken/collection/list
use aiken/fuzz.{int}
use aiken/merkle_patricia_forestry.{
  Tree, TreeBranch, TreeLeaf, compute_tree_hash,
}
use aiken/merkle_patricia_forestry/helpers.{combine, nibbles, suffix}
use aiken/merkle_patricia_forestry/merkling.{null_hash}
use aiken/primitive/bytearray

test learn() {
  let tree: Tree =
    TreeBranch {
      nibble: #"04",
      nodes: [
        Pair(
          0,
          TreeBranch {
            nibble: #"07",
            nodes: [
              Pair(
                6,
                TreeLeaf {
                  key: #"4076d8ab234597ab6a35c03c805381bbc016025b36ff1f7df9c5009e1a8b73ef",
                  value: "🤷",
                },
              ),
              Pair(
                12,
                TreeLeaf {
                  key: #"407c58473af4b3e5b24e65481294b0772ed6a7dd793937c6c90179960d154a22",
                  value: "🥝",
                },
              ),
            ],
          },
        ),
        Pair(
          10,
          TreeLeaf {
            key: #"4a522f84bcda4bebb725d5f2b92af615b57cc1777bb0d8b2c6c18c3e3e6520cd",
            value: "🤷",
          },
        ),
      ],
    }

  compute_tree_hash(tree, #"") == #"83a5c96888616bc2be9e65b6fab3673d57a862467f89ac14294aec2f2bc73ae3"
}
