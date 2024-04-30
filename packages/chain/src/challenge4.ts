import { RuntimeModule, runtimeModule, state, runtimeMethod } from "@proto-kit/module";
import { assert, StateMap, State, Option } from "@proto-kit/protocol";
import { UInt64 } from "@proto-kit/library";
import { Struct, Field, PublicKey, Bool, Experimental, Poseidon, Nullifier, MerkleMapWitness, MerkleWitness, MerkleTree } from "o1js";


export class MessagePublicOutput extends Struct({
  agentId: Field,
  securityCodeHash: Field,
  messageNumber: UInt64,
}) { }

export function verifyMessage(
  agentId: Field,
  message: Message,
): MessagePublicOutput {

  // The message is of the correct length - assuming it can't have leading zeros?  Not exactly clear on requirement
  assert(message.twelveChars.greaterThanOrEqual(100000000000), "Twelve chars is not 12 characters long!");
  assert(message.twelveChars.lessThanOrEqual(999999999999), "Twelve chars is not 12 characters long!");

  const securityCodeHash = Poseidon.hash([message.securityCode]);

  return new MessagePublicOutput({
    agentId: agentId,
    securityCodeHash: securityCodeHash,
    messageNumber: message.messageNumber,
  });
}

// Not exactly clear what 'twelveChars' is, I asked in Slack but never got a response
// Assuming it's a field that should be exactly twelve decimal characters long with no leading zeroes
export class Message extends Struct({ agentId: Field, messageNumber: UInt64, twelveChars: Field, securityCode: Field }) { }

export const messageZKP = Experimental.ZkProgram({
  publicOutput: MessagePublicOutput,
  methods: {
    verifyMessage: {
      privateInputs: [Field, Message],
      method: verifyMessage,
    },
  },
});
export class MessageProof extends Experimental.ZkProgram.Proof(messageZKP) { }

// This will be the stored state for each agent
export class AgentInfo extends Struct({ messageNumber: UInt64, securityCodeHash: Field, blockHeight: UInt64, nonce: UInt64, sender: PublicKey }) { }

@runtimeModule()
export class AgentMessageStore extends RuntimeModule<unknown> {

  @state() public agentMap = StateMap.from<Field, AgentInfo>(
    Field,
    AgentInfo
  );

  @state() public adminAddr = State.from<PublicKey>(PublicKey);

  /*
  After contract initialization, the administrator should claim
  the contract by calling this method.  Then nobody else will
  be able to add agents
  */
  @runtimeMethod()
  public claimAdmin(
  ): void {
    const currAdmin = this.adminAddr.get();
    const adminExists: Bool = currAdmin.isSome;
    assert(adminExists.not(), "Admin already claimed!");
    this.adminAddr.set(this.transaction.sender.value);
  }

  @runtimeMethod()
  public initializeAgent(
    agentId: Field,
    securityCodeHash: Field,
  ): void {
    // Make sure only admin can add new agents
    const currAdmin = this.adminAddr.get();
    assert(currAdmin.isSome, "Admin must exist!");
    assert(this.transaction.sender.value.equals(currAdmin.value), "Only admin can add agents!");

    // Initialize with 0 for all fields
    const newAgentInfo = new AgentInfo({
      messageNumber: UInt64.from(0),
      securityCodeHash: securityCodeHash,
      blockHeight: UInt64.from(0),
      nonce: UInt64.from(0),
      sender: PublicKey.empty()
    });
    this.agentMap.set(agentId, newAgentInfo);
  }

  @runtimeMethod()
  public processMessageProof(msgProof: MessageProof) {
    // Make sure proof was valid
    msgProof.verify();

    // Now make the update using those inputs
    const sender: PublicKey = this.transaction.sender.value;
    const nonce = this.transaction.nonce.value;
    const blockHeight = this.network.block.height.value;

    const messageNumber = msgProof.publicOutput.messageNumber
    const agentId = msgProof.publicOutput.agentId
    const securityCodeHash = msgProof.publicOutput.securityCodeHash

    const agentInfo: Option<AgentInfo> = this.agentMap.get(agentId);
    // The agentId exists in the system
    assert(agentInfo.isSome, "Agent does not exist!");

    const agentInfoObj = new AgentInfo(agentInfo.value);

    // We need to do two checks here:
    // First the check here that the messageNumber is higher than previous
    assert(agentInfoObj.messageNumber.lessThan(UInt64.from(messageNumber)), "Message number too low!");
    // Second check that the security code hash matches that held for that AgentID
    assert(agentInfoObj.securityCodeHash.equals(securityCodeHash), "Security code does not match!");

    agentInfoObj.messageNumber = UInt64.from(messageNumber);
    agentInfoObj.sender = sender;
    agentInfoObj.nonce = UInt64.from(nonce);
    agentInfoObj.blockHeight = UInt64.from(blockHeight);
    this.agentMap.set(agentId, agentInfoObj);
  }
}
