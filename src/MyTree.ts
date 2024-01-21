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
  Bool,
  Poseidon,
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

  @method addValue(leafWitness: MerkleWitness8, valueAfter: Field) {
    const rootNow = this.treeRoot.get();
    this.treeRoot.requireEquals(rootNow);

    // compute the root after incrementing
    const rootAfter = leafWitness.calculateRoot(valueAfter);

    // set the new root
    this.treeRoot.set(rootAfter);
  }

  @method deposit(leafWitness: MerkleWitness8, secret: Field) {
    const rootNow = this.treeRoot.get();
    this.treeRoot.requireEquals(rootNow);

    const sender = this.sender;
    Provable.log('Sender', sender);
    const hash = Poseidon.hash(sender.toFields());
    const computedRoot = leafWitness.calculateRoot(hash);
    computedRoot.assertEquals(rootNow, 'invalid root 1');

    const flags = this.checkFlags(secret);

    flags.assertTrue('Invalid flags');

    const received = this.messagesReceived.get();
    this.messagesReceived.requireEquals(received);
    this.messagesReceived.set(received.add(1));

    this.emitEvent('message-received', secret);
  }

  @method checkFlags(secret: Field): Bool {
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
    // flag1True * ( flag2True + flag2True + ... flag6True) = 0
    const check1 = flag1True
      .mul(
        flag2True.add(flag3True).add(flag4True).add(flag5True).add(flag6True)
      )
      .equals(Field(0));

    // If flag 2 is true, then flag 3 must also be true.
    // flag2True * (1 - flag3True) = 0
    const check2 = flag2True.mul(Field(1).sub(flag3True)).equals(Field(0));

    // If flag 4 is true, then flags 5 and 6 must be false.
    // flag4True * (flag5True + flag6True) = 0
    const check3 = flag4True.mul(flag5True.add(flag6True)).equals(Field(0));

    return check1.and(check2).and(check3);
  }
}
