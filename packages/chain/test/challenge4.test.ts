import { TestingAppChain } from "@proto-kit/sdk";
import { PrivateKey, Field, Poseidon } from "o1js";
import { AgentMessageStore, Message, MessageProof, MessagePublicOutput, verifyMessage } from "../src/challenge4";
import { Pickles } from "o1js/dist/node/snarky";
import { dummyBase64Proof } from "o1js/dist/node/lib/proof_system";
import { log } from "@proto-kit/common";
import { UInt64 } from "@proto-kit/library";

log.setLevel("ERROR");


// From Airdrop.test.ts example
async function mockProof(
  publicOutput: MessagePublicOutput
): Promise<MessageProof> {
  const [, proof] = Pickles.proofOfBase64(await dummyBase64Proof(), 2);
  return new MessageProof({
    proof: proof,
    maxProofsVerified: 2,
    publicInput: undefined,
    publicOutput,
  });
}

describe("agentMessagesStore", () => {
  it("should successfully store a message", async () => {
    const appChain = TestingAppChain.fromRuntime({
      AgentMessageStore,
    });

    appChain.configurePartial({
      Runtime: {
        AgentMessageStore: {},
        // If we don't configure balances we get an error?
        Balances: {
          totalSupply: UInt64.from(10000),
        },
      },
    });

    await appChain.start();

    // Insert basic agent...
    const alicePrivateKey = PrivateKey.random();
    const alice = alicePrivateKey.toPublicKey();

    appChain.setSigner(alicePrivateKey);

    const ams = appChain.runtime.resolve("AgentMessageStore");

    const agentId: Field = Field(123);
    const securityCode: Field = Field(345);
    const securityCodeHash: Field = Poseidon.hash([securityCode]);

    const tx0 = await appChain.transaction(alice, () => {
      ams.claimAdmin()
    });
    await tx0.sign();
    await tx0.send();
    const block0 = await appChain.produceBlock();
    expect(block0?.transactions[0].status.toBoolean()).toBe(true);

    const tx1 = await appChain.transaction(alice, () => {
      ams.initializeAgent(agentId, securityCodeHash)
    });
    await tx1.sign();
    await tx1.send();
    const block = await appChain.produceBlock();
    expect(block?.transactions[0].status.toBoolean()).toBe(true);

    const newMessage: Message = new Message({ agentId, messageNumber: UInt64.from(888), twelveChars: Field(123456789101), securityCode: securityCode });
    const messageOutput = verifyMessage(newMessage)
    const messageProof = await mockProof(messageOutput);

    const tx2 = await appChain.transaction(alice, () => {
      ams.processMessageProof(messageProof)
    });

    await tx2.sign();
    await tx2.send();
    const block2 = await appChain.produceBlock();
    expect(block2?.transactions[0].status.toBoolean()).toBe(true);

    // We should have updated the message number to 888
    const agentVal = await appChain.query.runtime.AgentMessageStore.agentMap.get(agentId);
    expect(agentVal?.messageNumber.toBigInt()).toBe(888n);
    // Also check sender, nonce, blockHeight...
    expect(agentVal?.sender).toEqual(alice);
    expect(agentVal?.nonce.toBigInt()).toBe(2n);
    expect(agentVal?.blockHeight.toBigInt()).toBe(2n);

  }, 1_000_000);

  it("should fail on nonexistent agent", async () => {
    const appChain = TestingAppChain.fromRuntime({
      AgentMessageStore,
    });

    appChain.configurePartial({
      Runtime: {
        AgentMessageStore: {},
        Balances: {
          totalSupply: UInt64.from(10000),
        },
      },
    });

    await appChain.start();

    // Insert basic agent...
    const alicePrivateKey = PrivateKey.random();
    const alice = alicePrivateKey.toPublicKey();

    appChain.setSigner(alicePrivateKey);

    const ams = appChain.runtime.resolve("AgentMessageStore");

    // This agentId does NOT exist...
    const badAgentId: Field = Field(999);
    const securityCode: Field = Field(345);
    // const securityCodeHash: Field = Poseidon.hash([securityCode]);
    const newMessage: Message = new Message({ agentId: badAgentId, messageNumber: UInt64.from(888), twelveChars: Field(123456789101), securityCode: securityCode });
    const messageOutput = verifyMessage(newMessage)
    const messageProof = await mockProof(messageOutput);

    const tx3 = await appChain.transaction(alice, () => {
      ams.processMessageProof(messageProof)
    });
    await tx3.sign();
    await tx3.send();

    // Transaction should fail
    const block3 = await appChain.produceBlock();
    expect(block3?.transactions[0].status.toBoolean()).toBe(false);

    // And if we get the data it should be undefined?
    const agentVal2 = await appChain.query.runtime.AgentMessageStore.agentMap.get(badAgentId);
    expect(agentVal2).toBeUndefined();
  }, 1_000_000);


  it("should fail on bad security code", async () => {
    const appChain = TestingAppChain.fromRuntime({
      AgentMessageStore,
    });

    appChain.configurePartial({
      Runtime: {
        AgentMessageStore: {},
        Balances: {
          totalSupply: UInt64.from(10000),
        },
      },
    });

    await appChain.start();

    // Insert basic agent...
    const alicePrivateKey = PrivateKey.random();
    const alice = alicePrivateKey.toPublicKey();

    appChain.setSigner(alicePrivateKey);

    const ams = appChain.runtime.resolve("AgentMessageStore");

    const agentId: Field = Field(123);
    const securityCode: Field = Field(345);
    const securityCodeHash: Field = Poseidon.hash([securityCode]);

    const tx0 = await appChain.transaction(alice, () => {
      ams.claimAdmin()
    });
    await tx0.sign();
    await tx0.send();
    const block0 = await appChain.produceBlock();
    expect(block0?.transactions[0].status.toBoolean()).toBe(true);

    const tx1 = await appChain.transaction(alice, () => {
      ams.initializeAgent(agentId, securityCodeHash)
    });

    await tx1.sign();
    await tx1.send();
    const block = await appChain.produceBlock();
    expect(block?.transactions[0].status.toBoolean()).toBe(true);

    const badSecurityCode: Field = Field(999);
    const newMessage: Message = new Message({ agentId, messageNumber: UInt64.from(888), twelveChars: Field(123456789101), securityCode: badSecurityCode });
    const messageOutput = verifyMessage(newMessage)
    const messageProof = await mockProof(messageOutput);

    const tx2 = await appChain.transaction(alice, () => {
      ams.processMessageProof(messageProof)
    });

    await tx2.sign();
    await tx2.send();
    const block2 = await appChain.produceBlock();

    // Block where we send the bad security code should fail - we check the hash here...
    expect(block2?.transactions[0].status.toBoolean()).toBe(false);
    const err = block2?.transactions[0].statusMessage;
    expect(err).toContain("Security code does not match!");

  }, 1_000_000);


  it("should fail if we don't have twelve characters", async () => {
    const appChain = TestingAppChain.fromRuntime({
      AgentMessageStore,
    });

    appChain.configurePartial({
      Runtime: {
        AgentMessageStore: {},
        Balances: {
          totalSupply: UInt64.from(10000),
        },
      },
    });

    await appChain.start();

    // Insert basic agent...
    const alicePrivateKey = PrivateKey.random();
    const alice = alicePrivateKey.toPublicKey();

    appChain.setSigner(alicePrivateKey);

    const ams = appChain.runtime.resolve("AgentMessageStore");

    const agentId: Field = Field(123);
    const securityCode: Field = Field(345);
    const securityCodeHash: Field = Poseidon.hash([securityCode]);

    const tx0 = await appChain.transaction(alice, () => {
      ams.claimAdmin()
    });
    await tx0.sign();
    await tx0.send();
    const block0 = await appChain.produceBlock();
    expect(block0?.transactions[0].status.toBoolean()).toBe(true);

    const tx1 = await appChain.transaction(alice, () => {
      ams.initializeAgent(agentId, securityCodeHash)
    });

    await tx1.sign();
    await tx1.send();
    const block = await appChain.produceBlock();
    expect(block?.transactions[0].status.toBoolean()).toBe(true);

    const badTwelveCharsLow: Field = Field(12345);
    const badTwelveCharsHigh: Field = Field(123456789101234);
    const newMessage1: Message = new Message({ agentId, messageNumber: UInt64.from(888), twelveChars: badTwelveCharsLow, securityCode: securityCode });
    const newMessage2: Message = new Message({ agentId, messageNumber: UInt64.from(889), twelveChars: badTwelveCharsHigh, securityCode: securityCode });
    // Both of these should fail!
    try {
      verifyMessage(newMessage1)
      expect("TX SUCCESSFUL!").toMatch('TX DID NOT FAIL!');
    } catch (e: any) {
      const err_str = e.toString();
      // First message is too low, but for some reason it's inverting
      // the assertGreaterThanOrEqual into a assertLessThanOrEqual and throwing on that
      expect(err_str).toContain("Field.assertLessThan()");
    }

    try {
      verifyMessage(newMessage2)
      expect("TX SUCCESSFUL!").toMatch('TX DID NOT FAIL!');
    } catch (e: any) {
      const err_str = e.toString();
      // Second message is too high...
      expect(err_str).toContain("Field.assertLessThan()");
    }

  }, 1_000_000);


  it("should fail on message number that is too low", async () => {
    const appChain = TestingAppChain.fromRuntime({
      AgentMessageStore,
    });

    appChain.configurePartial({
      Runtime: {
        AgentMessageStore: {},
        Balances: {
          totalSupply: UInt64.from(10000),
        },
      },
    });

    await appChain.start();

    // Insert basic agent...
    const alicePrivateKey = PrivateKey.random();
    const alice = alicePrivateKey.toPublicKey();

    appChain.setSigner(alicePrivateKey);

    const ams = appChain.runtime.resolve("AgentMessageStore");

    const agentId: Field = Field(123);
    const securityCode: Field = Field(345);
    const securityCodeHash: Field = Poseidon.hash([securityCode]);

    const tx0 = await appChain.transaction(alice, () => {
      ams.claimAdmin()
    });
    await tx0.sign();
    await tx0.send();
    const block0 = await appChain.produceBlock();
    expect(block0?.transactions[0].status.toBoolean()).toBe(true);

    const tx1 = await appChain.transaction(alice, () => {
      ams.initializeAgent(agentId, securityCodeHash)
    });

    await tx1.sign();
    await tx1.send();
    const block = await appChain.produceBlock();

    // So have this one be successful...
    const newMessage: Message = new Message({ agentId, messageNumber: UInt64.from(888), twelveChars: Field(123456789101), securityCode: securityCode });
    const messageOutput = verifyMessage(newMessage)
    const messageProof = await mockProof(messageOutput);

    const tx2 = await appChain.transaction(alice, () => {
      ams.processMessageProof(messageProof)
    });

    await tx2.sign();
    await tx2.send();
    const block2 = await appChain.produceBlock();

    expect(block?.transactions[0].status.toBoolean()).toBe(true);
    expect(block2?.transactions[0].status.toBoolean()).toBe(true);

    // Now send a low message number
    const messageNumberTooLow: UInt64 = UInt64.from(800);
    const newMessage2: Message = new Message({ agentId, messageNumber: messageNumberTooLow, twelveChars: Field(123456789101), securityCode: securityCode });
    const messageOutput2 = verifyMessage(newMessage2)
    const messageProof2 = await mockProof(messageOutput2);

    const tx3 = await appChain.transaction(alice, () => {
      ams.processMessageProof(messageProof2)
    });

    await tx3.sign();
    await tx3.send();
    const block3 = await appChain.produceBlock();

    // Block should have failed
    expect(block3?.transactions[0].status.toBoolean()).toBe(false);
    const err = block3?.transactions[0].statusMessage;
    expect(err).toContain("Message number too low!");

    // And message number should still be 888
    const agentVal = await appChain.query.runtime.AgentMessageStore.agentMap.get(agentId);
    expect(agentVal?.messageNumber.toBigInt()).toBe(888n);

  }, 1_000_000);

});