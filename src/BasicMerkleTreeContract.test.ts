import {
  AccountUpdate,
  Field,
  MerkleTree,
  MerkleWitness,
  Mina,
  PrivateKey,
} from 'o1js';
import { BasicMerkleTreeContract } from './BasicMerkleTreeContract';

let proofsEnabled = false;

describe('BasicMerkleTreeContract.js', () => {
  describe('BasicMerkleTreeContract()', () => {
    it('aaa', async () => {
      const Local = Mina.LocalBlockchain({ proofsEnabled });
      Mina.setActiveInstance(Local);
      const { privateKey: deployerKey, publicKey: deployerAccount } =
        Local.testAccounts[0];
      const { privateKey: senderPrivateKey, publicKey: senderPublicKey } =
        Local.testAccounts[1];

      const zkAppPrivateKey = PrivateKey.random();
      const zkAppPublicKey = zkAppPrivateKey.toPublicKey();

      const basicTreeZkAppPrivateKey = PrivateKey.random();
      const basicTreeZkAppAddress = basicTreeZkAppPrivateKey.toPublicKey();

      // initialize the zkapp
      const zkApp = new BasicMerkleTreeContract(basicTreeZkAppAddress);
      if (proofsEnabled) await BasicMerkleTreeContract.compile();

      // create a new tree
      const height = 20;
      const tree = new MerkleTree(height);
      class MerkleWitness20 extends MerkleWitness(height) {}

      // deploy the smart contract
      const deployTxn = await Mina.transaction(deployerAccount, () => {
        AccountUpdate.fundNewAccount(deployerAccount);
        zkApp.deploy();
        // get the root of the new tree to use as the initial tree root
        zkApp.initState(tree.getRoot());
      });
      await deployTxn.prove();
      deployTxn.sign([deployerKey, basicTreeZkAppPrivateKey]);

      const pendingDeployTx = await deployTxn.send();
      /**
       * `txn.send()` returns a pending transaction with two methods - `.wait()` and `.hash()`
       * `.hash()` returns the transaction hash
       * `.wait()` automatically resolves once the transaction has been included in a block. this is redundant for the LocalBlockchain, but very helpful for live testnets
       */
      //await pendingDeployTx.wait();

      const incrementIndex = 522n;
      const incrementAmount = Field(9);

      // get the witness for the current tree
      const witness = new MerkleWitness20(tree.getWitness(incrementIndex));

      // update the leaf locally
      tree.setLeaf(incrementIndex, incrementAmount);

      // update the smart contract
      const txn1 = await Mina.transaction(senderPublicKey, () => {
        zkApp.update(
          witness,
          Field(0), // leafs in new trees start at a state of 0
          incrementAmount
        );
      });
      await txn1.prove();
      const pendingTx = await txn1
        .sign([senderPrivateKey, zkAppPrivateKey])
        .send();
      await pendingTx.wait();

      // compare the root of the smart contract tree to our local tree
      console.log(
        `BasicMerkleTree: local tree root hash after send1: ${tree.getRoot()}`
      );
      console.log(
        `BasicMerkleTree: smart contract root hash after send1: ${zkApp.treeRoot.get()}`
      );
    });
  });
});
