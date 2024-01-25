from web3 import Web3
import json

class ServiceNodeRewardContract:
    def __init__(self):
        self.provider_url = "http://127.0.0.1:8545"
        self.private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" # Hardhat account #0
        self.web3 = Web3(Web3.HTTPProvider(self.provider_url))
        self.contract_address = self.getContractDeployedInLatestBlock()
        self.contract = self.web3.eth.contract(address=self.contract_address, abi=contract_abi)
        self.acc = self.web3.eth.account.from_key(self.private_key)
        unsent_tx = self.contract.functions.start().build_transaction({
            "from": self.acc.address,
            'nonce': self.web3.eth.get_transaction_count(self.acc.address)})
        signed_tx = self.web3.eth.account.sign_transaction(unsent_tx, private_key=self.acc.key)
        tx_hash = self.web3.eth.send_raw_transaction(signed_tx.rawTransaction)

    def call_function(self, function_name, *args, **kwargs):
        contract_function = self.contract.functions[function_name](*args)
        return contract_function.call(**kwargs)

    # Add more methods as needed to interact with the smart contract
    def getContractDeployedInLatestBlock(self):
        latest_block = self.web3.eth.get_block('latest')

        for tx_hash in latest_block['transactions']:
            try:
                tx_receipt = self.web3.eth.get_transaction_receipt(tx_hash)
                if tx_receipt.contractAddress:
                    return tx_receipt.contractAddress
            except TransactionNotFound:
                continue

        raise RuntimeError("No contracts deployed in latest block")

    def hardhatAccountAddress(self):
        return self.acc.address

    def addBLSPublicKey(self, args):
        # function addBLSPublicKey(uint256 pkX, uint256 pkY, uint256 sigs0, uint256 sigs1, uint256 sigs2, uint256 sigs3, uint256 serviceNodePubkey, uint256 serviceNodeSignature) public {
        unsent_tx = self.contract.functions.addBLSPublicKey(int(args["bls_pubkey"][:64], 16),
                                      int(args["bls_pubkey"][64:128], 16),
                                      int(args["proof_of_possession"][:64], 16),
                                      int(args["proof_of_possession"][64:128], 16),
                                      int(args["proof_of_possession"][128:192], 16),
                                      int(args["proof_of_possession"][192:256], 16),
                                      int(args["service_node_pubkey"], 16),
                                      # int(args["service_node_signature"], 16)
                                      int(0)
                    ).build_transaction({
                        "from": self.acc.address,
                        'nonce': self.web3.eth.get_transaction_count(self.acc.address)})
        signed_tx = self.web3.eth.account.sign_transaction(unsent_tx, private_key=self.acc.key)
        tx_hash = self.web3.eth.send_raw_transaction(signed_tx.rawTransaction)
        self.web3.eth.wait_for_transaction_receipt(tx_hash)
        return tx_hash

contract_abi = json.loads("""
[ {
      "inputs": [
        {
          "internalType": "address",
          "name": "_token",
          "type": "address"
        },
        {
          "internalType": "address",
          "name": "_foundationPool",
          "type": "address"
        },
        {
          "internalType": "uint256",
          "name": "_stakingRequirement",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "_liquidatorRewardRatio",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "_poolShareOfLiquidationRatio",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "_recipientRatio",
          "type": "uint256"
        }
      ],
      "stateMutability": "nonpayable",
      "type": "constructor"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "target",
          "type": "address"
        }
      ],
      "name": "AddressEmptyCode",
      "type": "error"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "account",
          "type": "address"
        }
      ],
      "name": "AddressInsufficientBalance",
      "type": "error"
    },
    {
      "inputs": [],
      "name": "ArrayLengthMismatch",
      "type": "error"
    },
    {
      "inputs": [
        {
          "internalType": "uint64",
          "name": "serviceNodeID",
          "type": "uint64"
        }
      ],
      "name": "BLSPubkeyAlreadyExists",
      "type": "error"
    },
    {
      "inputs": [],
      "name": "ContractNotActive",
      "type": "error"
    },
    {
      "inputs": [
        {
          "internalType": "uint64",
          "name": "serviceNodeID",
          "type": "uint64"
        },
        {
          "internalType": "address",
          "name": "recipient",
          "type": "address"
        }
      ],
      "name": "EarlierLeaveRequestMade",
      "type": "error"
    },
    {
      "inputs": [],
      "name": "FailedInnerCall",
      "type": "error"
    },
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "numSigners",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "requiredSigners",
          "type": "uint256"
        }
      ],
      "name": "InsufficientBLSSignatures",
      "type": "error"
    },
    {
      "inputs": [],
      "name": "InvalidBLSProofOfPossession",
      "type": "error"
    },
    {
      "inputs": [],
      "name": "InvalidBLSSignature",
      "type": "error"
    },
    {
      "inputs": [],
      "name": "InvalidParameter",
      "type": "error"
    },
    {
      "inputs": [
        {
          "internalType": "uint64",
          "name": "serviceNodeID",
          "type": "uint64"
        },
        {
          "internalType": "uint256",
          "name": "timestamp",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "currenttime",
          "type": "uint256"
        }
      ],
      "name": "LeaveRequestTooEarly",
      "type": "error"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "owner",
          "type": "address"
        }
      ],
      "name": "OwnableInvalidOwner",
      "type": "error"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "account",
          "type": "address"
        }
      ],
      "name": "OwnableUnauthorizedAccount",
      "type": "error"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "expectedRecipient",
          "type": "address"
        },
        {
          "internalType": "address",
          "name": "providedRecipient",
          "type": "address"
        },
        {
          "internalType": "uint256",
          "name": "serviceNodeID",
          "type": "uint256"
        }
      ],
      "name": "RecipientAddressDoesNotMatch",
      "type": "error"
    },
    {
      "inputs": [
        {
          "internalType": "uint64",
          "name": "serviceNodeID",
          "type": "uint64"
        }
      ],
      "name": "RecipientAddressNotProvided",
      "type": "error"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "token",
          "type": "address"
        }
      ],
      "name": "SafeERC20FailedOperation",
      "type": "error"
    },
    {
      "inputs": [
        {
          "internalType": "uint64",
          "name": "serviceNodeID",
          "type": "uint64"
        }
      ],
      "name": "ServiceNodeDoesntExist",
      "type": "error"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": true,
          "internalType": "uint64",
          "name": "serviceNodeID",
          "type": "uint64"
        },
        {
          "components": [
            {
              "internalType": "uint256",
              "name": "X",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "Y",
              "type": "uint256"
            }
          ],
          "indexed": false,
          "internalType": "struct BN256G1.G1Point",
          "name": "pubkey",
          "type": "tuple"
        }
      ],
      "name": "NewSeededServiceNode",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": true,
          "internalType": "uint64",
          "name": "serviceNodeID",
          "type": "uint64"
        },
        {
          "indexed": false,
          "internalType": "address",
          "name": "recipient",
          "type": "address"
        },
        {
          "components": [
            {
              "internalType": "uint256",
              "name": "X",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "Y",
              "type": "uint256"
            }
          ],
          "indexed": false,
          "internalType": "struct BN256G1.G1Point",
          "name": "pubkey",
          "type": "tuple"
        },
        {
          "indexed": false,
          "internalType": "uint256",
          "name": "serviceNodePubkey",
          "type": "uint256"
        },
        {
          "indexed": false,
          "internalType": "uint256",
          "name": "serviceNodeSignature",
          "type": "uint256"
        }
      ],
      "name": "NewServiceNode",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": true,
          "internalType": "address",
          "name": "previousOwner",
          "type": "address"
        },
        {
          "indexed": true,
          "internalType": "address",
          "name": "newOwner",
          "type": "address"
        }
      ],
      "name": "OwnershipTransferred",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": true,
          "internalType": "address",
          "name": "recipientAddress",
          "type": "address"
        },
        {
          "indexed": false,
          "internalType": "uint256",
          "name": "amount",
          "type": "uint256"
        },
        {
          "indexed": false,
          "internalType": "uint256",
          "name": "previousBalance",
          "type": "uint256"
        }
      ],
      "name": "RewardsBalanceUpdated",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": true,
          "internalType": "address",
          "name": "recipientAddress",
          "type": "address"
        },
        {
          "indexed": false,
          "internalType": "uint256",
          "name": "amount",
          "type": "uint256"
        }
      ],
      "name": "RewardsClaimed",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": true,
          "internalType": "uint64",
          "name": "serviceNodeID",
          "type": "uint64"
        },
        {
          "indexed": false,
          "internalType": "address",
          "name": "recipient",
          "type": "address"
        },
        {
          "components": [
            {
              "internalType": "uint256",
              "name": "X",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "Y",
              "type": "uint256"
            }
          ],
          "indexed": false,
          "internalType": "struct BN256G1.G1Point",
          "name": "pubkey",
          "type": "tuple"
        }
      ],
      "name": "ServiceNodeLiquidated",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": true,
          "internalType": "uint64",
          "name": "serviceNodeID",
          "type": "uint64"
        },
        {
          "indexed": false,
          "internalType": "address",
          "name": "recipient",
          "type": "address"
        },
        {
          "components": [
            {
              "internalType": "uint256",
              "name": "X",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "Y",
              "type": "uint256"
            }
          ],
          "indexed": false,
          "internalType": "struct BN256G1.G1Point",
          "name": "pubkey",
          "type": "tuple"
        }
      ],
      "name": "ServiceNodeRemoval",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": true,
          "internalType": "uint64",
          "name": "serviceNodeID",
          "type": "uint64"
        },
        {
          "indexed": false,
          "internalType": "address",
          "name": "recipient",
          "type": "address"
        },
        {
          "components": [
            {
              "internalType": "uint256",
              "name": "X",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "Y",
              "type": "uint256"
            }
          ],
          "indexed": false,
          "internalType": "struct BN256G1.G1Point",
          "name": "pubkey",
          "type": "tuple"
        }
      ],
      "name": "ServiceNodeRemovalRequest",
      "type": "event"
    },
    {
      "inputs": [],
      "name": "IsActive",
      "outputs": [
        {
          "internalType": "bool",
          "name": "",
          "type": "bool"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "LIST_END",
      "outputs": [
        {
          "internalType": "uint64",
          "name": "",
          "type": "uint64"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "MAX_SERVICE_NODE_REMOVAL_WAIT_TIME",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "pkX",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "pkY",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "sigs0",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "sigs1",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "sigs2",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "sigs3",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "serviceNodePubkey",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "serviceNodeSignature",
          "type": "uint256"
        }
      ],
      "name": "addBLSPublicKey",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "aggregate_pubkey",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "X",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "Y",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "blsNonSignerThreshold",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "recipientAddress",
          "type": "address"
        },
        {
          "internalType": "uint256",
          "name": "balance",
          "type": "uint256"
        }
      ],
      "name": "buildRecipientMessage",
      "outputs": [
        {
          "internalType": "bytes",
          "name": "",
          "type": "bytes"
        }
      ],
      "stateMutability": "pure",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "claimRewards",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "designatedToken",
      "outputs": [
        {
          "internalType": "contract IERC20",
          "name": "",
          "type": "address"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "foundationPool",
      "outputs": [
        {
          "internalType": "contract IERC20",
          "name": "",
          "type": "address"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint64",
          "name": "serviceNodeID",
          "type": "uint64"
        }
      ],
      "name": "initiateRemoveBLSPublicKey",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint64",
          "name": "serviceNodeID",
          "type": "uint64"
        },
        {
          "internalType": "uint256",
          "name": "sigs0",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "sigs1",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "sigs2",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "sigs3",
          "type": "uint256"
        },
        {
          "internalType": "uint64[]",
          "name": "ids",
          "type": "uint64[]"
        }
      ],
      "name": "liquidateBLSPublicKeyWithSignature",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "liquidateTag",
      "outputs": [
        {
          "internalType": "bytes32",
          "name": "",
          "type": "bytes32"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "nextServiceNodeID",
      "outputs": [
        {
          "internalType": "uint64",
          "name": "",
          "type": "uint64"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "owner",
      "outputs": [
        {
          "internalType": "address",
          "name": "",
          "type": "address"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "proofOfPossessionTag",
      "outputs": [
        {
          "internalType": "bytes32",
          "name": "",
          "type": "bytes32"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "",
          "type": "address"
        }
      ],
      "name": "recipients",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "rewards",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "claimed",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "removalTag",
      "outputs": [
        {
          "internalType": "bytes32",
          "name": "",
          "type": "bytes32"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint64",
          "name": "serviceNodeID",
          "type": "uint64"
        }
      ],
      "name": "removeBLSPublicKeyAfterWaitTime",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint64",
          "name": "serviceNodeID",
          "type": "uint64"
        },
        {
          "internalType": "uint256",
          "name": "sigs0",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "sigs1",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "sigs2",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "sigs3",
          "type": "uint256"
        },
        {
          "internalType": "uint64[]",
          "name": "ids",
          "type": "uint64[]"
        }
      ],
      "name": "removeBLSPublicKeyWithSignature",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "renounceOwnership",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "rewardTag",
      "outputs": [
        {
          "internalType": "bytes32",
          "name": "",
          "type": "bytes32"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint256[]",
          "name": "pkX",
          "type": "uint256[]"
        },
        {
          "internalType": "uint256[]",
          "name": "pkY",
          "type": "uint256[]"
        },
        {
          "internalType": "uint256[]",
          "name": "amounts",
          "type": "uint256[]"
        }
      ],
      "name": "seedPublicKeyList",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "bytes",
          "name": "",
          "type": "bytes"
        }
      ],
      "name": "serviceNodeIDs",
      "outputs": [
        {
          "internalType": "uint64",
          "name": "",
          "type": "uint64"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint64",
          "name": "",
          "type": "uint64"
        }
      ],
      "name": "serviceNodes",
      "outputs": [
        {
          "internalType": "uint64",
          "name": "next",
          "type": "uint64"
        },
        {
          "internalType": "uint64",
          "name": "previous",
          "type": "uint64"
        },
        {
          "internalType": "address",
          "name": "recipient",
          "type": "address"
        },
        {
          "components": [
            {
              "internalType": "uint256",
              "name": "X",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "Y",
              "type": "uint256"
            }
          ],
          "internalType": "struct BN256G1.G1Point",
          "name": "pubkey",
          "type": "tuple"
        },
        {
          "internalType": "uint256",
          "name": "leaveRequestTimestamp",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "deposit",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "serviceNodesLength",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "count",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "start",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "totalNodes",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "newOwner",
          "type": "address"
        }
      ],
      "name": "transferOwnership",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "recipientAddress",
          "type": "address"
        },
        {
          "internalType": "uint256",
          "name": "recipientAmount",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "sigs0",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "sigs1",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "sigs2",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "sigs3",
          "type": "uint256"
        },
        {
          "internalType": "uint64[]",
          "name": "ids",
          "type": "uint64[]"
        }
      ],
      "name": "updateRewardsBalance",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "updateServiceNodesLength",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    }
  ]
""")
