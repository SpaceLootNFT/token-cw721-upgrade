use cosmwasm_std::{Binary, StdResult, to_binary, CosmosMsg, WasmMsg, Addr};
use cw721::Expiration;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct InstantiateMsg {
    /// name of the NFT contract
    pub name: String,
    /// symbol of the NFT contract
    pub symbol: String,

    /// The minter is the only one who can create new NFTs.
    /// This is designed for a base NFT that is controlled by an external program
    /// or contract. You will likely replace this with custom logic in custom NFTs
    pub minter: String
}

/// This is like Cw721HandleMsg but we add a Mint command for an owner
/// to make this stand-alone. You will likely want to remove mint and
/// use other control logic in any contract that inherits this.
#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    /// Transfer is a base message to move a token to another account without triggering actions
    TransferNft {
        recipient: String,
        token_id: String,
    },
    /// Send is a base message to transfer a token to a contract and trigger an action
    /// on the receiving contract.
    SendNft {
        contract: String,
        token_id: String,
        msg: Binary,
    },
    /// Allows operator to transfer / send the token from the owner's account.
    /// If expiration is set, then this allowance has a time/height limit
    Approve {
        spender: String,
        token_id: String,
        expires: Option<Expiration>,
    },
    /// Remove previously granted Approval
    Revoke {
        spender: String,
        token_id: String,
    },
    /// Allows operator to transfer / send any token from the owner's account.
    /// If expiration is set, then this allowance has a time/height limit
    ApproveAll {
        operator: String,
        expires: Option<Expiration>,
    },
    /// Remove previously granted ApproveAll permission
    RevokeAll { operator: String },

    /// Mint a new NFT, can only be called by the contract minter
    Mint {
        /// Unique ID of the NFT
        token_id: String,
        /// The owner of the newly minter NFT
        owner: String,
        /// Identifies the asset to which this NFT represents
        name: String,
        /// Describes the asset to which this NFT represents (may be empty)
        description: Option<String>,
        /// A URI pointing to an image representing the asset
        image: Option<String>,
    },
    MintAdditional {
        /// Unique ID of the NFT
        token_id: String,
        /// The owner of the newly minter NFT
        owner: String,
        /// Identifies the asset to which this NFT represents
        name: String,
        /// Describes the asset to which this NFT represents (may be empty)
        description: Option<String>,
        /// A URI pointing to an image representing the asset
        image: Option<String>,
        /// token uri for additional data
        uri: Option<String>,
        /// metadata in json format
        metadata: Option<String>,
        /// creator address
        creator: Option<String>,
        /// royaltee fee in percent
        royalty_percent_fee: Option<u64>
    },
    ChangeMinter {
        minter: String
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    /// Return the owner of the given token, error if token does not exist
    /// Return type: OwnerOfResponse
    OwnerOf {
        token_id: String,
    },
    /// List all operators that can access all of the owner's tokens
    /// Return type: `ApprovedForAllResponse`
    ApprovedForAll {
        owner: String,
        start_after: Option<String>,
        limit: Option<u32>,
    },
    /// Total number of tokens issued
    NumTokens {},

    /// With MetaData Extension.
    /// Returns top-level metadata about the contract: `ContractInfoResponse`
    ContractInfo {},
    /// With MetaData Extension.
    /// Returns metadata about one particular token, based on *ERC721 Metadata JSON Schema*
    /// but directly from the contract: `NftInfoResponse`
    NftInfo {
        token_id: String,
    },
    /// With MetaData Extension.
    /// Returns metadata about one particular token, based on *ERC721 Metadata JSON Schema*
    /// but directly from the contract: `NftAdditionalInfoResponse`
    NftAdditionalInfo {
        token_id: String,
    },
    /// With MetaData Extension.
    /// Returns the result of both `NftInfo` and `OwnerOf` as one query as an optimization
    /// for clients: `AllNftInfo`
    AllNftInfo {
        token_id: String,
    },

    /// With Enumerable extension.
    /// Returns all tokens owned by the given address, [] if unset.
    /// Return type: TokensResponse.
    Tokens {
        owner: String,
        start_after: Option<String>,
        limit: Option<u32>,
    },
    /// With Enumerable extension.
    /// Requires pagination. Lists all token_ids controlled by the contract.
    /// Return type: TokensResponse.
    AllTokens {
        start_after: Option<String>,
        limit: Option<u32>,
    },

    /// Return total token own by address
    /// Return type: NumTokensResponse 
    Balance {
        owner: String
    },

    // Return the minter
    Minter {},
}

/// Shows who can mint these tokens
#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
pub struct MinterResponse {
    pub minter: String,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
pub struct NftAdditionalInfoResponse {
    pub owner: String,
    pub token_id: String,
    /// Identifies the asset to which this NFT represents
    pub name: String,
    /// Describes the asset to which this NFT represents
    pub description: String,
    /// "A URI pointing to a resource with mime type image/* representing the asset to which this
    /// NFT represents. Consider making any images at a width between 320 and 1080 pixels and aspect
    /// ratio between 1.91:1 and 4:5 inclusive.
    /// TODO: Use https://docs.rs/url_serde for type-safety
    pub image: Option<String>,
    pub uri: Option<String>,
    pub metadata: Option<String>,
    pub creator: Option<String>,
    pub royalty_percent_fee: Option<u64>
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct MigrateMsg {}

/// Cw721ReceiveMsg should be de/serialized under `Receive()` variant in a HandleMsg
#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub struct Cw721ReceiveMsg {
    pub sender: String,
    pub token_id: String,
    pub msg: Binary,
}

impl Cw721ReceiveMsg {
    /// serializes the message
    pub fn into_binary(self) -> StdResult<Binary> {
        let msg = ReceiverHandleMsg::ReceiveNft(self);
        to_binary(&msg)
    }

    /// creates a cosmos_msg sending this struct to the named contract
    pub fn into_cosmos_msg(self, contract_addr: String) -> StdResult<CosmosMsg> {
        let msg = self.into_binary()?;
        let execute = WasmMsg::Execute {
            contract_addr,
            msg,
            funds: vec![],
        };
        Ok(execute.into())
    }
}

/// This is just a helper to properly serialize the above message.
/// The actual receiver should include this variant in the larger HandleMsg enum
#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
enum ReceiverHandleMsg {
    ReceiveNft(Cw721ReceiveMsg),
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct InitHook {
    pub msg: Binary,
    pub contract_addr: String,
}