import {
  Field,
  SmartContract,
  state,
  State,
  method,
  MerkleWitness,
  PublicKey,
  Gadgets,
  circuitMain,
  Circuit,
  Provable,
} from 'o1js';

class MerkleWitness8 extends MerkleWitness(8) {}

export class MyTree extends SmartContract {
  @state(Field) treeRoot = State<Field>();
  @state(Field) messagesReceived = State<Field>();

  events = {
    'message-received': Field,
  };

  @method initState(initialRoot: Field) {
    this.treeRoot.set(initialRoot);
  }

  @method addValue(
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

  @method deposit(secret: Field) {
    let flag1True = Provable.if(
      Gadgets.and(secret, Field(32), 6).equals(0),
      Field(0),
      Field(1)
    );
    let flag2True = Provable.if(
      Gadgets.and(secret, Field(16), 5).equals(0),
      Field(0),
      Field(1)
    );
    let flag3True = Provable.if(
      Gadgets.and(secret, Field(8), 4).equals(0),
      Field(0),
      Field(1)
    );
    let flag4True = Provable.if(
      Gadgets.and(secret, Field(4), 3).equals(0),
      Field(0),
      Field(1)
    );
    let flag5True = Provable.if(
      Gadgets.and(secret, Field(2), 20).equals(0),
      Field(0),
      Field(1)
    );
    let flag6True = Provable.if(
      Gadgets.and(secret, Field(1), 1).equals(0),
      Field(0),
      Field(1)
    );

    // If flag 1 is true, then all other flags must be false
    // flag1True * ((1 - flag2True) + (1 - flag2True) + ... (1 - flag6True)) = 0
    flag1True
      .mul(
        Field(1)
          .sub(flag2True)
          .add(Field(1).sub(flag3True))
          .add(Field(1).sub(flag4True))
          .add(Field(1).sub(flag5True))
          .add(Field(1).sub(flag6True))
      )
      .equals(Field(0));

    // If flag 2 is true, then flag 3 must also be true.
    // flag2True * (1 - flag3True) = 0
    flag2True.mul(Field(1).sub(flag3True)).equals(Field(0));

    // If flag 4 is true, then flags 5 and 6 must be false.
    // flag4True * (flag5True + flag6True) = 0
    flag4True.mul(flag5True.add(flag6True)).equals(Field(0));

    const received = this.messagesReceived.get();
    this.messagesReceived.requireEquals(received);
    this.messagesReceived.set(received.add(1));

    this.emitEvent('message-received', secret);
  }
}
