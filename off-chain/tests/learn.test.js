import { inspect } from "node:util";
import assert from "node:assert";
import { DIGEST_LENGTH, digest } from "../lib/crypto.js";
import * as buffer from "node:buffer";
import test from "ava";
import {
  NULL_HASH,
  assertInstanceOf,
  commonPrefix,
  eachLine,
  intoPath,
  merkleProof,
  merkleRoot,
  nibble,
  nibbles,
  sparseVector,
  withEllipsis,
} from "../lib/helpers.js";
import { Leaf, Branch, Proof, Trie } from "../lib/trie.js";

const ACCOUNT_BALANCE_LIST = [
  {
    key: Buffer.from(
      "d8799f503450e8e7ff044148af0b0f151f490d99d8799f581c4ba6dd244255995969d2c05e323686bcbaba83b736e729941825d79bffd8799f581cec4574aacf96128597eff93ab9bc36c6bdc13d7f16ef5b62840ffa1fffff",
      "hex"
    ),
    value: Buffer.from("a0", "hex"),
  },
  {
    key: Buffer.from(
      "d8799f505bade4195c2e4136b9bca9b563725cadd8799f581cfdeb4bf0e8c077114a4553f1e05395e9fb7114db177f02f7b65c8de4ffd8799f581cfd92839136c47054fda09f2fbbb1792386a3b143cea5fca14fb8baceffff",
      "hex"
    ),
    value: Buffer.from(
      "a1581c5066154a102ee037390c5236f78db23239b49c5748d3d349f3ccf04ba14455534458192710",
      "hex"
    ),
  },
  {
    key: Buffer.from(
      "d8799f505bade4195c2e4136b9bca9b563725eeed8799f581c979a51682aec06f704ab144bbb50aded23d63790caa174b0e33aa545ffd8799f581ce8fbeb1a29c4a9aead8b68614f1f0fead352160f6a5d9925a7a89841ffff",
      "hex"
    ),
    value: Buffer.from("a140a1401864", "hex"),
  },
];

test("Trie.load", async (t) => {
  const trie = await Trie.fromList(ACCOUNT_BALANCE_LIST);
  const cbor = (await trie.toFullTreeCBOR()).toString("hex");
  console.log(cbor);
  // t.is(
  //   cbor,
  //   "d8799f4104a200d8799f4107a206d87a9f58204076d8ab234597ab6a35c03c805381bbc016025b36ff1f7df9c5009e1a8b73ef44f09fa4b7ff0cd87a9f5820407c58473af4b3e5b24e65481294b0772ed6a7dd793937c6c90179960d154a2244f09fa59dffff0ad87a9f58204a522f84bcda4bebb725d5f2b92af615b57cc1777bb0d8b2c6c18c3e3e6520cd44f09fa4b7ffff"
  // );
});

function verifyRootHash(trie) {
  const { rootHash, prefix, node } = trie;

  function computeNodeHash(nodeData) {
    if (nodeData === null) {
      return null;
    }

    if (!nodeData.node) {
      // Leaf node
      const value =
        typeof nodeData.value === "string"
          ? Buffer.from(nodeData.value)
          : nodeData.value;
      assertInstanceOf(Buffer, { value });
      const leafHash = computeLeafHash(nodeData.suffix, digest(value));
      return leafHash;
    } else {
      // branch node
      const childHashes = Object.values(nodeData.node).map((child) => {
        if (child != null) {
          return computeNodeHash(child);
        } else {
          return null;
        }
      });
      const root = merkleRoot(childHashes);
      const branchHash = computeBranchHash(nodeData.prefix, root);
      return branchHash;
    }
  }

  const computedRootHash = computeNodeHash({ node, prefix });
  return computedRootHash.toString("hex") === rootHash;
}

function computeLeafHash(suffix, value) {
  // NOTE:
  // We append the remaining prefix to the value. However, to make this
  // step more efficient on-chain, we append it as a raw bytestring instead of
  // an array of nibbles.
  //
  // If the prefix's length is odd however, we must still prepend one nibble, and
  // then the rest.
  const isOdd = suffix.length % 2 > 0;

  const head = isOdd
    ? Buffer.concat([Buffer.from([0x00]), nibbles(suffix.slice(0, 1))])
    : Buffer.from([0xff]);

  const tail = Buffer.from(isOdd ? suffix.slice(1) : suffix, "hex");

  assert(
    value.length === DIGEST_LENGTH,
    `value must be a ${DIGEST_LENGTH}-byte digest but it is ${value?.toString(
      "hex"
    )}`
  );
  return digest(Buffer.concat([head, tail, value]));
}

function computeBranchHash(prefix, root) {
  assert(
    root.length === DIGEST_LENGTH,
    `root must be a ${DIGEST_LENGTH}-byte digest but it is ${root?.toString(
      "hex"
    )}`
  );

  return digest(Buffer.concat([nibbles(prefix), root]));
}

function unindent(str) {
  const lines = str[0].split("\n").filter((n) => n.length > 0);
  const n = (lines[0] || "").length - (lines[0] || "").trimStart().length;
  return lines
    .map((s) => s.slice(n))
    .join("\n")
    .trimEnd();
}
