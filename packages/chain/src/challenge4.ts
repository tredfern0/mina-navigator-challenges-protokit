import { RuntimeModule, runtimeModule, state, runtimeMethod } from "@proto-kit/module";
import { assert, StateMap, State, Option } from "@proto-kit/protocol";
import { UInt64 } from "@proto-kit/library";
import { Struct, Field, PublicKey, Bool, Experimental, Poseidon, Nullifier, MerkleMapWitness, MerkleWitness, MerkleTree } from "o1js";


export class MessagePublicOutput extends Struct({
  agentId: Field,
  messageNumber: Field,
  root: Field,
}) { }

export const message: Field[] = [Field(0)];

// create a new tree
const height = 20;
const tree = new MerkleTree(height);
class MerkleWitness20 extends MerkleWitness(height) { }

export function canClaim(
  agentId: Field,
  witness: MerkleWitness20,
  messageDetails: Field,
): MessagePublicOutput {


  // TODO - 
  // we need to verify the other data here somehow... 


  // how can we check securityId...
  // need a merkleMap?  Actually yes that would work?


  // The security code matches that held for that AgentID
  assert(agentInfoObj.securityCode.equals(message.securityCode), "Security code does not match!");

  // The message is of the correct length - assuming it can't have leading zeros?  Not exactly clear on requirement
  assert(message.twelveChars.greaterThanOrEqual(100000000000), "Twelve chars is not 12 characters long!");
  assert(message.twelveChars.lessThanOrEqual(999999999999), "Twelve chars is not 12 characters long!");

  // The message number is greater than the highest so far for that agent.
  assert(agentInfoObj.messageNumber.lessThan(message.messageNumber), "Message number too low!");

  // You should update the agent state to store the last message number received.
  agentInfoObj.messageNumber = message.messageNumber;
  this.agentMap.set(agentId, agentInfoObj);



  // get the witness for the current tree
  // const witness = new MerkleWitness20(tree.getWitness(incrementIndex));

  // Verify witness - proves this is a valid agent
  const root = witness.calculateRoot(agentId);


  //const key = Poseidon.hash(nullifier.getPublicKey().toFields());
  // const [computedRoot, computedKey] = witness.computeRootAndKey(
  //   Bool(true).toField()
  // );
  // computedKey.assertEquals(key);

  // nullifier.verify(message);

  // Output:
  // agentId
  // message
  // something to verify merkle witness was valid...

  return new MessagePublicOutput({
    agentId: agentId,
    messageNumber: messageDetails,
    root: root,
  });
}

export const messageZKP = Experimental.ZkProgram({
  publicOutput: MessagePublicOutput,
  methods: {
    canClaim: {
      privateInputs: [MerkleMapWitness, Nullifier],
      method: canClaim,
    },
  },
});

export class MessageProof extends Experimental.ZkProgram.Proof(messageZKP) { }


// Not exactly clear what 'twelveChars' is, I asked in Slack but never got a response
// Assuming it's a field that should be exactly twelve decimal characters long with no leading zeroes
export class Message extends Struct({ agentId: Field, messageNumber: UInt64, twelveChars: Field, securityCode: Field }) { }

// This will be the stored state for each agent
export class AgentInfo extends Struct({ messageNumber: UInt64, securityCode: Field }) { }

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
    securityCode: Field,
  ): void {
    // Make sure only admin can add new agents
    const currAdmin = this.adminAddr.get();
    assert(currAdmin.isSome, "Admin must exist!");
    assert(this.transaction.sender.value.equals(currAdmin.value), "Only admin can add agents!");

    // Initialize with 0 for the messageNumber
    const newAgentInfo = new AgentInfo({ messageNumber: UInt64.from(0), securityCode });
    this.agentMap.set(agentId, newAgentInfo);
  }

  @runtimeMethod()
  public processMessage(
    agentId: Field,
    message: Message,
  ): void {

    const agentInfo: Option<AgentInfo> = this.agentMap.get(agentId);
    // The agentId exists in the system
    assert(agentInfo.isSome, "Agent does not exist!");

    const agentInfoObj = new AgentInfo(agentInfo.value);

    // The security code matches that held for that AgentID
    assert(agentInfoObj.securityCode.equals(message.securityCode), "Security code does not match!");

    // The message is of the correct length - assuming it can't have leading zeros?  Not exactly clear on requirement
    assert(message.twelveChars.greaterThanOrEqual(100000000000), "Twelve chars is not 12 characters long!");
    assert(message.twelveChars.lessThanOrEqual(999999999999), "Twelve chars is not 12 characters long!");

    // The message number is greater than the highest so far for that agent.
    assert(agentInfoObj.messageNumber.lessThan(message.messageNumber), "Message number too low!");

    // You should update the agent state to store the last message number received.
    agentInfoObj.messageNumber = message.messageNumber;
    this.agentMap.set(agentId, agentInfoObj);
  }


  @runtimeMethod()
  public processNew(msgProof: MessageProof) {
    msgProof.verify();

    // Make sure it was valid...
    const root = this.commitment.get();
    assert(msgProof.publicOutput.root.equals(root.value), "Root does not match!");

    // Now make the update using those inputs
    const sender: PublicKey = this.transaction.sender.value;
    const nonce = this.transaction.nonce.value;
    const blockHeight = this.network.block.height.value;

  }

}

