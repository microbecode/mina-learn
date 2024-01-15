import {
  Field,
  SmartContract,
  state,
  State,
  method,
  MerkleWitness,
  PublicKey,
} from 'o1js';

class MerkleWitness8 extends MerkleWitness(8) {}

export class MyTree extends SmartContract {
  @state(Field) treeRoot = State<Field>();

  @method initState(initialRoot: Field) {
    this.treeRoot.set(initialRoot);
  }

  @method update(
    leafWitness: MerkleWitness8,
    valueBefore: Field,
    valueAfter: Field
  ) {
    const initialRoot = this.treeRoot.get();
    this.treeRoot.requireEquals(initialRoot);

    // check the initial state matches what we expect
    const rootBefore = leafWitness.calculateRoot(valueBefore);
    rootBefore.assertEquals(initialRoot);

    // compute the root after incrementing
    const rootAfter = leafWitness.calculateRoot(valueAfter);

    // set the new root
    this.treeRoot.set(rootAfter);
  }
}
