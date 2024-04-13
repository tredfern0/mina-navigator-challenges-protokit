import { TestingAppChain } from "@proto-kit/sdk";
import { PrivateKey, Field } from "o1js";
import { AgentMessageStore, Message } from "../src/challenge3";
import { log } from "@proto-kit/common";
import { UInt64 } from "@proto-kit/library";

log.setLevel("ERROR");

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

    const tx1 = await appChain.transaction(alice, () => {
      ams.initializeAgent(agentId, securityCode)
    });

    await tx1.sign();
    await tx1.send();
    const block = await appChain.produceBlock();

    const newMessage: Message = new Message({ agentId, messageNumber: UInt64.from(888), twelveChars: Field(123456789101), securityCode: securityCode });

    const tx2 = await appChain.transaction(alice, () => {
      ams.processMessage(agentId, newMessage)
    });

    await tx2.sign();
    await tx2.send();
    const block2 = await appChain.produceBlock();

    expect(block?.transactions[0].status.toBoolean()).toBe(true);
    expect(block2?.transactions[0].status.toBoolean()).toBe(true);

    // We should have updated the message number to 888
    const agentVal = await appChain.query.runtime.AgentMessageStore.agentMap.get(agentId);
    expect(agentVal?.messageNumber.toBigInt()).toBe(888n);
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
    const newMessage: Message = new Message({ agentId: badAgentId, messageNumber: UInt64.from(888), twelveChars: Field(123456789101), securityCode: securityCode });
    const tx3 = await appChain.transaction(alice, () => {
      ams.processMessage(badAgentId, newMessage)
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

    const tx1 = await appChain.transaction(alice, () => {
      ams.initializeAgent(agentId, securityCode)
    });

    await tx1.sign();
    await tx1.send();
    const block = await appChain.produceBlock();

    const badSecurityCode: Field = Field(999);
    const newMessage: Message = new Message({ agentId, messageNumber: UInt64.from(888), twelveChars: Field(123456789101), securityCode: badSecurityCode });

    const tx2 = await appChain.transaction(alice, () => {
      ams.processMessage(agentId, newMessage)
    });

    await tx2.sign();
    await tx2.send();
    const block2 = await appChain.produceBlock();

    expect(block?.transactions[0].status.toBoolean()).toBe(true);
    // Block where we send the bad security code should fail
    expect(block2?.transactions[0].status.toBoolean()).toBe(false);
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

    const tx1 = await appChain.transaction(alice, () => {
      ams.initializeAgent(agentId, securityCode)
    });

    await tx1.sign();
    await tx1.send();
    const block = await appChain.produceBlock();

    const badTwelveCharsLow: Field = Field(12345);
    const badTwelveCharsHigh: Field = Field(123456789101234);
    const newMessage1: Message = new Message({ agentId, messageNumber: UInt64.from(888), twelveChars: badTwelveCharsLow, securityCode: securityCode });
    const newMessage2: Message = new Message({ agentId, messageNumber: UInt64.from(889), twelveChars: badTwelveCharsHigh, securityCode: securityCode });

    const tx2 = await appChain.transaction(alice, () => {
      ams.processMessage(agentId, newMessage1)
    });

    await tx2.sign();
    await tx2.send();
    const block2 = await appChain.produceBlock();

    const tx3 = await appChain.transaction(alice, () => {
      ams.processMessage(agentId, newMessage2)
    });

    await tx3.sign();
    await tx3.send();
    const block3 = await appChain.produceBlock();

    expect(block?.transactions[0].status.toBoolean()).toBe(true);
    // Both 2 and 3 should have failed
    expect(block2?.transactions[0].status.toBoolean()).toBe(false);
    expect(block3?.transactions[0].status.toBoolean()).toBe(false);
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

    const tx1 = await appChain.transaction(alice, () => {
      ams.initializeAgent(agentId, securityCode)
    });

    await tx1.sign();
    await tx1.send();
    const block = await appChain.produceBlock();

    // So have this one be successful...
    const newMessage: Message = new Message({ agentId, messageNumber: UInt64.from(888), twelveChars: Field(123456789101), securityCode: securityCode });

    const tx2 = await appChain.transaction(alice, () => {
      ams.processMessage(agentId, newMessage)
    });

    await tx2.sign();
    await tx2.send();
    const block2 = await appChain.produceBlock();

    expect(block?.transactions[0].status.toBoolean()).toBe(true);
    expect(block2?.transactions[0].status.toBoolean()).toBe(true);

    // Now send a low message number
    const messageNumberTooLow: UInt64 = UInt64.from(800);
    const newMessage2: Message = new Message({ agentId, messageNumber: messageNumberTooLow, twelveChars: Field(123456789101), securityCode: securityCode });

    const tx3 = await appChain.transaction(alice, () => {
      ams.processMessage(agentId, newMessage2)
    });

    await tx3.sign();
    await tx3.send();
    const block3 = await appChain.produceBlock();

    // Block should have failed
    expect(block3?.transactions[0].status.toBoolean()).toBe(false);

    // And message number should still be 888
    const agentVal = await appChain.query.runtime.AgentMessageStore.agentMap.get(agentId);
    expect(agentVal?.messageNumber.toBigInt()).toBe(888n);

  }, 1_000_000);

});