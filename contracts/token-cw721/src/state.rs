use cosmwasm_std::{CanonicalAddr, StdResult, Storage};
use cosmwasm_storage::{
    bucket, bucket_read, singleton, singleton_read, Bucket, ReadonlyBucket, ReadonlySingleton,
    Singleton,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cw721::{ContractInfoResponse, Expiration};

pub const CONFIG_KEY: &[u8] = b"config";
pub const MINTER_KEY: &[u8] = b"minter";
pub const CONTRACT_INFO_KEY: &[u8] = b"nft_info";
pub const NUM_TOKENS_KEY: &[u8] = b"num_tokens";

pub const TOKEN_PREFIX: &[u8] = b"tokens";
pub const TOKEN_ADDITIONAL_PREFIX: &[u8] = b"tokens_additional";
pub const OPERATOR_PREFIX: &[u8] = b"operators";

pub const OWNER_PREFIX: &[u8] = b"owner";
pub const NUM_OWNED: &[u8] = b"num_owned";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct TokenInfo {
    /// The owner of the newly minter NFT
    pub owner: CanonicalAddr,
    /// approvals are stored here, as we clear them all upon transfer and cannot accumulate much
    pub approvals: Vec<Approval>,

    /// Identifies the asset to which this NFT represents
    pub name: String,
    /// Describes the asset to which this NFT represents
    pub description: String,
    /// A URI pointing to an image representing the asset
    pub image: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct TokenAdditionalInfo {
    /// token uri for additional data
    pub uri: Option<String>,
    /// metadata in json format
    pub metadata: Option<String>,
    /// creator address for support royalty use case
    pub creator: Option<CanonicalAddr>,
    /// royalty fee percent in 5 decimal -> 100000 mean 100%
    pub royalty_percent_fee: Option<u64>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
pub struct Approval {
    /// Account that can transfer/send the token
    pub spender: CanonicalAddr,
    /// When the Approval expires (maybe Expiration::never)
    pub expires: Expiration,
}


pub fn contract_info(storage: &mut dyn Storage) -> Singleton<ContractInfoResponse> {
    singleton(storage, CONTRACT_INFO_KEY)
}

pub fn contract_info_read(storage: &dyn Storage) -> ReadonlySingleton<ContractInfoResponse> {
    singleton_read(storage, CONTRACT_INFO_KEY)
}

pub fn mint(storage: &mut dyn Storage) -> Singleton<CanonicalAddr> {
    singleton(storage, MINTER_KEY)
}

pub fn mint_read(storage: &dyn Storage) -> ReadonlySingleton<CanonicalAddr> {
    singleton_read(storage, MINTER_KEY)
}

fn token_count(storage: &mut dyn Storage) -> Singleton<u64> {
    singleton(storage, NUM_TOKENS_KEY)
}

fn token_count_read(storage: &dyn Storage) -> ReadonlySingleton<u64> {
    singleton_read(storage, NUM_TOKENS_KEY)
}

pub fn num_tokens(storage: & dyn Storage) -> StdResult<u64> {
    Ok(token_count_read(storage).may_load()?.unwrap_or_default())
}

pub fn increment_tokens(storage: &mut dyn Storage) -> StdResult<u64> {
    let val = num_tokens(storage)? + 1;
    token_count(storage).save(&val)?;
    Ok(val)
}

pub fn tokens(storage: &mut dyn Storage) -> Bucket<TokenInfo> {
    bucket(storage, TOKEN_PREFIX)
}

pub fn tokens_read(storage: &dyn Storage) -> ReadonlyBucket<TokenInfo> {
    bucket_read(storage, TOKEN_PREFIX)
}

pub fn tokens_additional(storage: &mut dyn Storage) -> Bucket<TokenAdditionalInfo> {
    bucket(storage, TOKEN_ADDITIONAL_PREFIX)
}

pub fn tokens_additional_read(storage: &dyn Storage) -> ReadonlyBucket<TokenAdditionalInfo> {
    bucket_read(storage, TOKEN_ADDITIONAL_PREFIX)
}

pub fn operators<'a>(
    storage: &'a mut dyn Storage,
    owner: &CanonicalAddr,
) -> Bucket<'a, Expiration> {
    Bucket::multilevel(storage, &[OPERATOR_PREFIX, owner.as_slice()])
}

pub fn operators_read<'a>(
    storage: &'a dyn Storage,
    owner: &CanonicalAddr,
) -> ReadonlyBucket<'a, Expiration> {
    ReadonlyBucket::multilevel(storage, &[OPERATOR_PREFIX, owner.as_slice()])
}

pub fn owned_count(storage: &mut dyn Storage) -> Bucket<u64> {
    bucket(storage, NUM_OWNED)
}

pub fn owned_count_read(storage: &dyn Storage) -> ReadonlyBucket<u64> {
    bucket_read(storage, NUM_OWNED)
}

pub fn owners<'a>(storage: &'a mut dyn Storage, owner: &CanonicalAddr) -> Bucket<'a, bool> {
    Bucket::multilevel(storage, &[OWNER_PREFIX, owner.as_slice()])
}

pub fn owners_read<'a>(
    storage: &'a dyn Storage,
    owner: &CanonicalAddr,
) -> ReadonlyBucket<'a, bool> {
    ReadonlyBucket::multilevel(storage, &[OWNER_PREFIX, owner.as_slice()])
}
