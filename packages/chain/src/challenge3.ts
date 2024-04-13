import { RuntimeModule, runtimeModule, state, runtimeMethod } from "@proto-kit/module";
import { State, assert, StateMap, Option } from "@proto-kit/protocol";
import { Balance, Balances as BaseBalances, TokenId, UInt64 } from "@proto-kit/library";

import { PublicKey, Struct, Field, Bool, Provable } from "o1js";

// Not exactly clear what 'twelveChars' is, I asked in Slack but never got a response
// Assuming it's a field that should be exactly twelve decimal characters long with no leading zeroes
export class Message extends Struct({ agentId: Field, messageNumber: UInt64, twelveChars: Field, securityCode: Field }) { }

// This will be the stored state for each agent
export class AgentInfo extends Struct({ messageNumber: UInt64, securityCode: Field }) { }

type AgentMessagesStoreConfig = Record<string, never>;

@runtimeModule()
export class AgentMessagesStore extends RuntimeModule<AgentMessagesStoreConfig> {

}
// So convert this to hte other one...
interface BalancesConfig {
  totalSupply: Balance;
}

// TODO - convert from 'Balances' to 'AgentMessagesStore'
@runtimeModule()
export class Balances extends BaseBalances<BalancesConfig> {

  @state() public agentMap = StateMap.from<Field, AgentInfo>(
    Field,
    AgentInfo
  );


  @runtimeMethod()
  public initializeAgent(
    agentId: Field,
    securityCode: Field,
  ): void {
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
}
