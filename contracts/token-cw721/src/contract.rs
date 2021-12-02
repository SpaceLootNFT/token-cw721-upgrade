use cosmwasm_std::{
    attr, entry_point, to_binary, Addr, Binary, CanonicalAddr, Deps, DepsMut,
    Env, MessageInfo, Order, Response, StdError, StdResult
};

use cw0::{calc_range_start_string};
use cw2::set_contract_version;
use cw721::{
    ApprovedForAllResponse, ContractInfoResponse, Expiration,
    NumTokensResponse, OwnerOfResponse, TokensResponse,
};
use loot::token::{
    Cw721ReceiveMsg, ExecuteMsg, InstantiateMsg, MigrateMsg, MinterResponse,
    NftAdditionalInfoResponse, QueryMsg,
};
use std::str::from_utf8;
use serde_json_wasm::{ from_str};

use crate::state::{
    contract_info, contract_info_read, increment_tokens, mint, mint_read, num_tokens, operators,
    operators_read, owned_count, owned_count_read, owners, owners_read, tokens, tokens_additional,
    tokens_additional_read, tokens_read, Approval, TokenAdditionalInfo, TokenInfo,
};
use crate::msg:: {
    NftInfoResponse, Metadata, Trait, AllNftInfoResponse, MetaDataAttribute
};

// version info for migration info
const CONTRACT_NAME: &str = "crates.io:cw721-base";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(deps: DepsMut, _env: Env, _info: MessageInfo, msg: InstantiateMsg) -> StdResult<Response> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    let info = ContractInfoResponse {
        name: msg.name,
        symbol: msg.symbol,
    };
    contract_info(deps.storage).save(&info)?;
    let minter = deps.api.addr_canonicalize(&msg.minter)?;
    mint(deps.storage).save(&minter)?;

    // callback to minter contract
    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(deps: DepsMut, env: Env, info: MessageInfo, msg: ExecuteMsg) -> StdResult<Response> {
    match msg {
        ExecuteMsg::Mint {
            token_id,
            owner,
            name,
            description,
            image,
        } => {
            let owner_addr = deps.api.addr_validate(&owner)?;
            handle_mint(
                deps,
                env,
                info,
                token_id,
                owner_addr,
                name,
                description,
                image,
                None,
                None,
                None,
                None,
            )
        }
        ExecuteMsg::MintAdditional {
            token_id,
            owner,
            name,
            description,
            image,
            uri,
            metadata,
            creator,
            royalty_percent_fee,
        } => {
            let owner_addr = deps.api.addr_validate(&owner)?;
            let creator_addr: Option<Addr> = match creator {
                Some(c) => Some(deps.api.addr_validate(&c.as_str())?),
                None => None,
            };
            handle_mint(
                deps,
                env,
                info,
                token_id,
                owner_addr,
                name,
                description,
                image,
                uri,
                metadata,
                creator_addr,
                royalty_percent_fee,
            )
        }
        ExecuteMsg::Approve {
            spender,
            token_id,
            expires,
        } => {
            let spender_addr = deps.api.addr_validate(&spender)?;
            handle_approve(deps, env, info, spender_addr, token_id, expires)
        }
        ExecuteMsg::Revoke { spender, token_id } => {
            let spender_addr = deps.api.addr_validate(&spender)?;
            handle_revoke(deps, env, info, spender_addr, token_id)
        }
        ExecuteMsg::ApproveAll { operator, expires } => {
            let operator_addr = deps.api.addr_validate(&operator)?;
            handle_approve_all(deps, env, info, operator_addr, expires)
        }
        ExecuteMsg::RevokeAll { operator } => {
            let operator_addr = deps.api.addr_validate(&operator)?;
            handle_revoke_all(deps, env, info, operator_addr)
        }
        ExecuteMsg::TransferNft {
            recipient,
            token_id,
        } => {
            let recipient_addr = deps.api.addr_validate(&recipient)?;
            handle_transfer_nft(deps, env, info, recipient_addr, token_id)
        }
        ExecuteMsg::SendNft {
            contract,
            token_id,
            msg,
        } => {
            let contract_addr = deps.api.addr_validate(&contract)?;
            handle_send_nft(deps, env, info, contract_addr, token_id, msg)
        }
        ExecuteMsg::ChangeMinter {
            minter
        } => {
            let minter_addr = deps.api.addr_validate(&minter)?;
            handle_change_minter(deps, env, info, minter_addr)
        }
    }
}

pub fn handle_mint(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    token_id: String,
    owner: Addr,
    name: String,
    description: Option<String>,
    image: Option<String>,
    uri: Option<String>,
    metadata: Option<String>,
    creator: Option<Addr>,
    royalty_percent_fee: Option<u64>,
) -> StdResult<Response> {
    let minter = mint(deps.storage).load()?;
    let sender_raw = deps.api.addr_canonicalize(&info.sender.as_str())?;

    if sender_raw != minter {
        return Err(StdError::generic_err("unauthorized"));
    }

    let owner_raw = deps.api.addr_canonicalize(&owner.as_str())?;
    // create the token
    let token = TokenInfo {
        owner: owner_raw.clone(),
        approvals: vec![],
        name,
        description: description.unwrap_or_default(),
        image,
    };
    tokens(deps.storage).update(token_id.as_bytes(), |old| match old {
        Some(_) => Err(StdError::generic_err("token_id already claimed")),
        None => Ok(token),
    })?;
    let creator_raw: Option<CanonicalAddr> = match creator {
        Some(c) => Some(deps.api.addr_canonicalize(&c.as_str())?),
        None => None,
    };
    let token_additional = TokenAdditionalInfo {
        uri: uri,
        metadata: metadata,
        creator: creator_raw,
        royalty_percent_fee: royalty_percent_fee,
    };
    tokens_additional(deps.storage).update(token_id.as_bytes(), |old| match old {
        Some(_) => Err(StdError::generic_err("token_id already claimed")),
        None => Ok(token_additional),
    })?;

    increment_tokens(deps.storage)?;

    owners(deps.storage, &owner_raw).save(token_id.as_bytes(), &true)?;
    let mut count = owned_count_read(deps.storage)
        .may_load(owner_raw.as_slice())?
        .unwrap_or_default();
    count = count + 1;
    owned_count(deps.storage).save(owner_raw.as_slice(), &count)?;

    Ok(Response::new().add_attributes(vec![
        attr("action", "mint"),
        attr("minter", info.sender),
        attr("token_id", token_id),
    ]))
}

pub fn handle_transfer_nft(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    recipient: Addr,
    token_id: String,
) -> StdResult<Response> {
    _transfer_nft(deps, &env, &info, &recipient, &token_id)?;

    Ok(Response::new().add_attributes(vec![
        attr("action", "transfer_nft"),
        attr("sender", info.sender),
        attr("recipient", recipient),
        attr("token_id", token_id),
    ]))
}

pub fn handle_send_nft(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    contract: Addr,
    token_id: String,
    msg: Binary,
) -> StdResult<Response> {
    // Unwrap message first
    let send = Cw721ReceiveMsg {
        sender: info.sender.to_string().clone(),
        token_id: token_id.clone(),
        msg: msg,
    };

    // Transfer token
    _transfer_nft(deps, &env, &info, &contract, &token_id)?;

    // Send message
    Ok(Response::new()
        .add_message(send.into_cosmos_msg(contract.to_string())?)
        .add_attribute("action", "send_nft")
        .add_attribute("sender", info.sender)
        .add_attribute("recipient", contract)
        .add_attribute("token_id", token_id))
}

pub fn _transfer_nft(
    deps: DepsMut,
    env: &Env,
    info: &MessageInfo,
    recipient: &Addr,
    token_id: &str,
) -> StdResult<TokenInfo> {
    let mut token = tokens(deps.storage).load(token_id.as_bytes())?;
    // ensure we have permissions
    check_can_send(deps.as_ref(), env, info, &token)?;
    // remove old owner
    let owner_raw = token.owner.clone();
    owners(deps.storage, &owner_raw).remove(token_id.as_bytes());
    let mut count = owned_count_read(deps.storage)
        .may_load(owner_raw.as_slice())?
        .unwrap_or_default();
    count = count - 1;
    owned_count(deps.storage).save(owner_raw.as_slice(), &count)?;
    // set owner and remove existing approvals
    let recipient_raw = deps.api.addr_canonicalize(recipient.as_str())?;
    token.owner = recipient_raw.clone();
    token.approvals = vec![];
    tokens(deps.storage).save(token_id.as_bytes(), &token)?;
    // add new owner
    owners(deps.storage, &recipient_raw).save(token_id.as_bytes(), &true)?;
    let mut count = owned_count_read(deps.storage)
        .may_load(recipient_raw.as_slice())?
        .unwrap_or_default();
    count = count + 1;
    owned_count(deps.storage).save(recipient_raw.as_slice(), &count)?;
    Ok(token)
}

pub fn handle_approve(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    spender: Addr,
    token_id: String,
    expires: Option<Expiration>,
) -> StdResult<Response> {
    _update_approvals(deps, &env, &info, &spender, &token_id, true, expires)?;

    Ok(Response::new().add_attributes(vec![
        attr("action", "approve"),
        attr("sender", info.sender),
        attr("spender", spender),
        attr("token_id", token_id),
    ]))
}

pub fn handle_revoke(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    spender: Addr,
    token_id: String,
) -> StdResult<Response> {
    _update_approvals(deps, &env, &info, &spender, &token_id, false, None)?;

    Ok(Response::new().add_attributes(vec![
        attr("action", "revoke"),
        attr("sender", info.sender),
        attr("spender", spender),
        attr("token_id", token_id),
    ]))
}

pub fn _update_approvals(
    deps: DepsMut,
    env: &Env,
    info: &MessageInfo,
    spender: &Addr,
    token_id: &str,
    // if add == false, remove. if add == true, remove then set with this expiration
    add: bool,
    expires: Option<Expiration>,
) -> StdResult<TokenInfo> {
    let mut token = tokens(deps.storage).load(token_id.as_bytes())?;
    // ensure we have permissions
    check_can_approve(deps.as_ref(), &env, &info, &token)?;

    // update the approval list (remove any for the same spender before adding)
    let spender_raw = deps.api.addr_canonicalize(&spender.as_str())?;
    token.approvals = token
        .approvals
        .into_iter()
        .filter(|apr| apr.spender != spender_raw)
        .collect();

    // only difference between approve and revoke
    if add {
        // reject expired data as invalid
        let expires = expires.unwrap_or_default();
        if expires.is_expired(&env.block) {
            return Err(StdError::generic_err(
                "Cannot set approval that is already expired",
            ));
        }
        let approval = Approval {
            spender: spender_raw,
            expires,
        };
        token.approvals.push(approval);
    }

    tokens(deps.storage).save(token_id.as_bytes(), &token)?;

    Ok(token)
}

pub fn handle_approve_all(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    operator: Addr,
    expires: Option<Expiration>,
) -> StdResult<Response> {
    // reject expired data as invalid
    let expires = expires.unwrap_or_default();
    if expires.is_expired(&env.block) {
        return Err(StdError::generic_err(
            "Cannot set approval that is already expired",
        ));
    }

    // set the operator for us
    let sender_raw = deps.api.addr_canonicalize(&info.sender.as_str())?;
    let operator_raw = deps.api.addr_canonicalize(&operator.as_str())?;
    operators(deps.storage, &sender_raw).save(operator_raw.as_slice(), &expires)?;

    Ok(Response::new().add_attributes(vec![
        attr("action", "approve_all"),
        attr("sender", info.sender),
        attr("operator", operator),
    ]))
}

pub fn handle_revoke_all(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    operator: Addr,
) -> StdResult<Response> {
    let sender_raw = deps.api.addr_canonicalize(&info.sender.as_str())?;
    let operator_raw = deps.api.addr_canonicalize(&operator.as_str())?;
    operators(deps.storage, &sender_raw).remove(operator_raw.as_slice());

    Ok(Response::new().add_attributes(vec![
        attr("action", "revoke_all"),
        attr("sender", info.sender),
        attr("operator", operator),
    ]))
}

pub fn handle_change_minter(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    minter: Addr
) -> StdResult<Response> {
    let existing_minter = mint(deps.storage).load()?;
    let sender_raw = deps.api.addr_canonicalize(&info.sender.as_str())?;

    if sender_raw != existing_minter {
        return Err(StdError::generic_err("unauthorized"));
    }

    let minter_raw = deps.api.addr_canonicalize(&minter.as_str())?;
    mint(deps.storage).save(&minter_raw)?;
    
    Ok(Response::new()
    .add_attribute("action", "change_minter")
    .add_attribute("new_minter", minter))
}

/// returns true iff the sender can execute approve or reject on the contract
fn check_can_approve(
    deps: Deps,
    env: &Env,
    info: &MessageInfo,
    token: &TokenInfo,
) -> StdResult<()> {
    // owner can approve
    let sender_raw = deps.api.addr_canonicalize(&info.sender.as_str())?;
    if token.owner == sender_raw {
        return Ok(());
    }
    // operator can approve
    let op = operators_read(deps.storage, &token.owner).may_load(sender_raw.as_slice())?;
    match op {
        Some(ex) => {
            if ex.is_expired(&env.block) {
                Err(StdError::generic_err("unauthorized"))
            } else {
                Ok(())
            }
        }
        None => Err(StdError::generic_err("unauthorized")),
    }
}

/// returns true iff the sender can transfer ownership of the token
fn check_can_send(deps: Deps, env: &Env, info: &MessageInfo, token: &TokenInfo) -> StdResult<()> {
    // owner can send
    let sender_raw = deps.api.addr_canonicalize(&info.sender.as_str())?;
    if token.owner == sender_raw {
        return Ok(());
    }

    // any non-expired token approval can send
    if token
        .approvals
        .iter()
        .any(|apr| apr.spender == sender_raw && !apr.expires.is_expired(&env.block))
    {
        return Ok(());
    }

    // operator can send
    let op = operators_read(deps.storage, &token.owner).may_load(sender_raw.as_slice())?;
    match op {
        Some(ex) => {
            if ex.is_expired(&env.block) {
                Err(StdError::generic_err("unauthorized"))
            } else {
                Ok(())
            }
        }
        None => Err(StdError::generic_err("unauthorized")),
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env:Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::Minter {} => to_binary(&query_minter(deps)?),
        QueryMsg::ContractInfo {} => to_binary(&query_contract_info(deps)?),
        QueryMsg::NftInfo { token_id } => to_binary(&query_nft_info(deps, token_id)?),
        QueryMsg::NftAdditionalInfo { token_id } => {
            to_binary(&query_nft_additional_info(deps, token_id)?)
        }
        QueryMsg::OwnerOf { token_id } => to_binary(&query_owner_of(deps, token_id)?),
        QueryMsg::AllNftInfo { token_id } => to_binary(&query_all_nft_info(deps, token_id)?),
        QueryMsg::ApprovedForAll {
            owner,
            start_after,
            limit,
        } => {
            let owner_addr = deps.api.addr_validate(&owner)?;
            to_binary(&query_all_approvals(deps, owner_addr, start_after, limit)?)
        }
        QueryMsg::NumTokens {} => to_binary(&query_num_tokens(deps)?),
        QueryMsg::AllTokens { start_after, limit } => {
            to_binary(&query_all_tokens(deps, start_after, limit)?)
        }
        QueryMsg::Tokens {
            owner,
            start_after,
            limit,
        } => {
            let owner_addr = deps.api.addr_validate(&owner)?;
            to_binary(&query_tokens(deps, owner_addr, start_after, limit)?)
        }
        QueryMsg::Balance { owner } => {
            let owner_addr = deps.api.addr_validate(&owner)?;
            to_binary(&query_num_owned(deps, owner_addr)?)
        }
    }
}

fn query_minter(deps: Deps) -> StdResult<MinterResponse> {
    let minter_raw = mint_read(deps.storage).load()?;
    let minter = deps.api.addr_humanize(&minter_raw)?;
    Ok(MinterResponse {
        minter: minter.to_string(),
    })
}

fn query_contract_info(deps: Deps) -> StdResult<ContractInfoResponse> {
    contract_info_read(deps.storage).load()
}

fn query_num_tokens(deps: Deps) -> StdResult<NumTokensResponse> {
    let count = num_tokens(deps.storage)?;
    Ok(NumTokensResponse { count })
}

fn query_nft_info(deps: Deps, token_id: String) -> StdResult<NftInfoResponse> {
    let info = tokens_read(deps.storage).load(token_id.as_bytes())?;
    let additional = tokens_additional_read(deps.storage).load(token_id.as_bytes())?;
    // convert additional info to cw721 standard
    Ok(convert_cw721(deps, info.clone(), additional.clone())?)
}

fn convert_cw721(
    _deps:Deps, 
    info: TokenInfo,
    additional: TokenAdditionalInfo
) -> StdResult<NftInfoResponse> {
    let mut traits:Vec<Trait> = vec![];
    let mut attributes:Option<Vec<Trait>> = None;
    let mut metadata_json = match additional.metadata {
        Some(v) => v,
        None => "".to_string()
    };
    if !metadata_json.is_empty() {
        if metadata_json.contains(":null}") {
            metadata_json = str::replace(&metadata_json, ":null}", ":\"\"}");
        }
        let metadatas = from_str::<Vec<MetaDataAttribute>>(&metadata_json).expect("json not well-formatted");
        for metadata in metadatas.iter() {
            traits.push(Trait {
                display_type: None,
                trait_type: metadata.name.replace("\"",""),
                value: metadata.value.replace("\"","")
            });
        }
        attributes = Some(traits);
    }
    let cw721_info = NftInfoResponse {
        token_uri: additional.uri,
        extension: Some(Metadata {
            name: Some(info.name),
            description: Some(info.description),
            external_url: None,
            image: info.image,
            image_data: None,
            background_color: None,
            animation_url: None,
            youtube_url: None,
            attributes: attributes
        })
    };
    Ok(cw721_info)
}

fn query_nft_additional_info(deps: Deps, token_id: String) -> StdResult<NftAdditionalInfoResponse> {
    let info = tokens_read(deps.storage).load(token_id.as_bytes())?;
    let additional = tokens_additional_read(deps.storage).load(token_id.as_bytes())?;
    let creator: Option<String> = match additional.creator {
        Some(c) => Some(deps.api.addr_humanize(&c)?.to_string()),
        None => None,
    };
    Ok(NftAdditionalInfoResponse {
        owner: deps.api.addr_humanize(&info.owner)?.to_string(),
        token_id: token_id.clone(),
        name: info.name,
        description: info.description,
        image: info.image,
        uri: additional.uri,
        metadata: additional.metadata,
        creator: creator,
        royalty_percent_fee: additional.royalty_percent_fee,
    })
}

fn query_owner_of(deps: Deps, token_id: String) -> StdResult<OwnerOfResponse> {
    let info = tokens_read(deps.storage).load(token_id.as_bytes())?;
    Ok(OwnerOfResponse {
        owner: deps.api.addr_humanize(&info.owner)?.to_string(),
        approvals: humanize_approvals(deps, &info)?,
    })
}

const DEFAULT_LIMIT: u32 = 10;
const MAX_LIMIT: u32 = 30;

fn query_all_approvals(
    deps: Deps,
    owner: Addr,
    start_after: Option<String>,
    limit: Option<u32>,
) -> StdResult<ApprovedForAllResponse> {
    let owner_raw = deps.api.addr_canonicalize(&owner.as_str())?;
    let limit = limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT) as usize;
    let start = calc_range_start_human(deps, start_after)?;

    let res: StdResult<Vec<_>> = operators_read(deps.storage, &owner_raw)
        .range(start.as_deref(), None, Order::Ascending)
        .take(limit)
        .map(|item| {
            item.and_then(|(k, expires)| {
                Ok(cw721::Approval {
                    spender: deps.api.addr_humanize(&k.into())?.to_string(),
                    expires,
                })
            })
        })
        .collect();
    Ok(ApprovedForAllResponse { operators: res? })
}

fn query_all_tokens(
    deps: Deps,
    start_after: Option<String>,
    limit: Option<u32>,
) -> StdResult<TokensResponse> {
    let limit = limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT) as usize;
    let start = calc_range_start_string(start_after);

    let tokens: StdResult<Vec<String>> = tokens_read(deps.storage)
        .range(start.as_deref(), None, Order::Ascending)
        .take(limit)
        .map(|item| item.map(|(k, _)| String::from_utf8_lossy(&k).to_string()))
        .collect();
    Ok(TokensResponse { tokens: tokens? })
}

fn query_all_nft_info(deps: Deps, token_id: String) -> StdResult<AllNftInfoResponse> {
    let info = tokens_read(deps.storage).load(token_id.as_bytes())?;
    let additional = tokens_additional_read(deps.storage).load(token_id.as_bytes())?;
    Ok(AllNftInfoResponse {
        access: OwnerOfResponse {
            owner: deps.api.addr_humanize(&info.owner)?.to_string(),
            approvals: humanize_approvals(deps, &info)?,
        },
        info: convert_cw721(deps, info.clone(), additional.clone())?,
    })
}

pub fn query_tokens(
    deps: Deps,
    owner: Addr,
    start_after: Option<String>,
    limit: Option<u32>,
) -> StdResult<TokensResponse> {
    let limit = limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT) as usize;
    let start = calc_range_start_string(start_after);
    let owner_raw = deps.api.addr_canonicalize(&owner.as_str())?;

    let res: StdResult<Vec<String>> = owners_read(deps.storage, &owner_raw)
        .range(start.as_deref(), None, Order::Ascending)
        .take(limit)
        .map(|item| {
            item.and_then(|(k, _)| {
                let result = from_utf8(&k);
                let token_id = match result {
                    Ok(t) => t,
                    Err(_) => &"",
                };
                Ok(token_id.to_string())
            })
        })
        .collect();
    Ok(TokensResponse { tokens: res? })
}

pub fn query_num_owned(deps: Deps, owner: Addr) -> StdResult<NumTokensResponse> {
    let owner_raw = deps.api.addr_canonicalize(&owner.as_str())?;

    let count = owned_count_read(deps.storage)
        .may_load(owner_raw.as_slice())?
        .unwrap_or_default();
    Ok(NumTokensResponse { count })
}

fn humanize_approvals(deps: Deps, info: &TokenInfo) -> StdResult<Vec<cw721::Approval>> {
    info.approvals
        .iter()
        .map(|apr| humanize_approval(deps, apr))
        .collect()
}

fn humanize_approval(deps: Deps, approval: &Approval) -> StdResult<cw721::Approval> {
    Ok(cw721::Approval {
        spender: deps.api.addr_humanize(&approval.spender)?.to_string(),
        expires: approval.expires,
    })
}

fn calc_range_start_human(
    deps: Deps,
    start_after: Option<String>,
) -> StdResult<Option<Vec<u8>>> {
    match start_after {
        Some(human) => {
            let mut v: Vec<u8> = deps.api.addr_canonicalize(&human)?.0.into();
            v.push(0);
            Ok(Some(v))
        }
        None => Ok(None),
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(_deps: DepsMut, _env: Env, _msg: MigrateMsg) -> StdResult<Response> {
    Ok(Response::default())
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{from_binary, CosmosMsg, StdError, WasmMsg, Api};

    use super::*;
    use cw721::ApprovedForAllResponse;

    const MINTER: &str = "merlin";
    const CONTRACT_NAME: &str = "Magic Power";
    const SYMBOL: &str = "MGK";

    fn setup_contract(deps: DepsMut) {
        let msg = InstantiateMsg {
            name: CONTRACT_NAME.to_string(),
            symbol: SYMBOL.to_string(),
            minter: MINTER.into()
        };
        let info = mock_info("creator", &[]);
        let env = mock_env();
        let res = instantiate(deps, env, info, msg).unwrap();
        assert_eq!(0, res.messages.len());
    }

    #[test]
    fn proper_initialization() {
        let mut deps = mock_dependencies(&[]);

        let msg = InstantiateMsg {
            name: CONTRACT_NAME.to_string(),
            symbol: SYMBOL.to_string(),
            minter: MINTER.into()
        };
        let env = mock_env();
        let info = mock_info("creator", &[]);

        // we can just call .unwrap() to assert this was a success
        let res = instantiate(deps.as_mut(), env, info, msg).unwrap();
        assert_eq!(0, res.messages.len());

        // it worked, let's query the state
        let res = query_minter(deps.as_ref()).unwrap();
        assert_eq!(MINTER, res.minter.as_str());
        let info = query_contract_info(deps.as_ref()).unwrap();
        assert_eq!(
            info,
            ContractInfoResponse {
                name: CONTRACT_NAME.to_string(),
                symbol: SYMBOL.to_string(),
            }
        );

        let count = query_num_tokens(deps.as_ref()).unwrap();
        assert_eq!(0, count.count);

        // list the token_ids
        let tokens = query_all_tokens(deps.as_ref(), None, None).unwrap();
        assert_eq!(0, tokens.tokens.len());
    }

    #[test]
    fn minting() {
        let mut deps = mock_dependencies(&[]);
        setup_contract(deps.as_mut());

        let token_id = "petrify".to_string();
        let name = "Petrify with Gaze".to_string();
        let description = "Allows the owner to petrify anyone looking at him or her".to_string();

        let mint_msg = ExecuteMsg::Mint {
            token_id: token_id.clone(),
            owner: "medusa".into(),
            name: name.clone(),
            description: Some(description.clone()),
            image: None,
        };

        // random cannot mint
        let random = mock_info("random", &[]);
        let err = execute(deps.as_mut(), mock_env(), random, mint_msg.clone()).unwrap_err();
        match err {
            StdError::GenericErr { .. } => {}
            e => panic!("unexpected error: {}", e),
        }

        // minter can mint
        let allowed = mock_env();
        let info = mock_info(MINTER, &[]);
        let _ = execute(deps.as_mut(), allowed, info, mint_msg.clone()).unwrap();

        // ensure num tokens increases
        let count = query_num_tokens(deps.as_ref()).unwrap();
        assert_eq!(1, count.count);

        // unknown nft returns error
        let _ = query_nft_info(deps.as_ref(), "unknown".to_string()).unwrap_err();

        // this nft info is correct
        let info = query_nft_info(deps.as_ref(), token_id.clone()).unwrap();
        assert_eq!(
            info,
            NftInfoResponse {
                token_uri: None,
                extension: Some(Metadata {
                    image: None,
                    image_data: None,
                    external_url: None,
                    description: Some("Allows the owner to petrify anyone looking at him or her".to_string()),
                    name: Some("Petrify with Gaze".to_string()),
                    attributes: None,
                    background_color: None,
                    animation_url: None,
                    youtube_url: None
                })
            }
        );

        // owner info is correct
        let owner = query_owner_of(deps.as_ref(), token_id.clone()).unwrap();
        assert_eq!(
            owner,
            OwnerOfResponse {
                owner: "medusa".into(),
                approvals: vec![],
            }
        );

        // Cannot mint same token_id again
        let mint_msg2 = ExecuteMsg::Mint {
            token_id: token_id.clone(),
            owner: "hercules".into(),
            name: "copy cat".into(),
            description: None,
            image: None,
        };

        let allowed = mock_env();
        let info = mock_info(MINTER, &[]);
        let err = execute(deps.as_mut(), allowed, info, mint_msg2).unwrap_err();
        match err {
            StdError::GenericErr { msg, .. } => {
                assert_eq!(msg.as_str(), "token_id already claimed")
            }
            e => panic!("unexpected error: {}", e),
        }

        // list the token_ids
        let tokens = query_all_tokens(deps.as_ref(), None, None).unwrap();
        assert_eq!(1, tokens.tokens.len());
        assert_eq!(vec![token_id], tokens.tokens);

        let tokens = query_tokens(deps.as_ref(), Addr::unchecked("medusa"), None, None).unwrap();
        assert_eq!(1, tokens.tokens.len());
        assert_eq!("petrify".to_string(), tokens.tokens[0]);
        let count = query_num_owned(deps.as_ref(), Addr::unchecked("medusa")).unwrap();
        assert_eq!(1, count.count);

        // mint again with additional information
        let token_id = "test".to_string();
        let name = "hello world nft".to_string();
        let description = "some random text here".to_string();
        let uri = "https://helloworld".to_string();
        let metadata = "[{\"name\":\"hello\",\"value\":\"world\",\"rarity\":\"test\"}]".to_string();

        let mint_msg3 = ExecuteMsg::MintAdditional {
            token_id: token_id.clone(),
            owner: "test".into(),
            name: name.clone(),
            description: Some(description.clone()),
            image: None,
            uri: Some(uri.clone()),
            metadata: Some(metadata.clone()),
            creator: Some("artist".into()),
            royalty_percent_fee: Some(1000),
        };
        let allowed = mock_env();
        let info = mock_info(MINTER, &[]);
        //let _ = execute(deps.as_mut(), allowed, info, mint_msg3.clone()).unwrap();
        let _ = execute(deps.as_mut(), allowed, info, mint_msg3.clone()).unwrap();

        // ensure num tokens increases
        let count = query_num_tokens(deps.as_ref()).unwrap();
        assert_eq!(2, count.count);

        // unknown nft returns error
        let _ = query_nft_additional_info(deps.as_ref(), "unknown".to_string()).unwrap_err();

        // this nft info is correct
        let info = query_nft_info(deps.as_ref(), token_id.clone()).unwrap();
        assert_eq!(
            info,
            NftInfoResponse {
                token_uri: Some("https://helloworld".to_string()),
                extension: Some(Metadata {
                    image: None,
                    image_data: None,
                    external_url: None,
                    description: Some("some random text here".to_string()),
                    name: Some("hello world nft".to_string()),
                    attributes: Some(vec![
                        Trait {
                            trait_type: "hello".to_string(),
                            value: "world".to_string(),
                            display_type: None
                        }
                    ]),
                    background_color: None,
                    animation_url: None,
                    youtube_url: None
                })
            }
        );
        // this nft additional info is correct
        let info = query_nft_additional_info(deps.as_ref(), token_id.clone()).unwrap();
        assert_eq!(
            info,
            NftAdditionalInfoResponse {
                token_id: token_id.clone(),
                owner: "test".into(),
                name: name.clone(),
                description: description.clone(),
                image: None,
                uri: Some(uri.clone()),
                metadata: Some(metadata.clone()),
                creator: Some("artist".into()),
                royalty_percent_fee: Some(1000)
            }
        );

        // owner info is correct
        let owner = query_owner_of(deps.as_ref(), token_id.clone()).unwrap();
        assert_eq!(
            owner,
            OwnerOfResponse {
                owner: "test".into(),
                approvals: vec![],
            }
        );
    }

    #[test]
    fn transferring_nft() {
        let mut deps = mock_dependencies(&[]);
        setup_contract(deps.as_mut());

        // Mint a token
        let token_id = "melt".to_string();
        let name = "Melting power".to_string();
        let description = "Allows the owner to melt anyone looking at him or her".to_string();

        let mint_msg = ExecuteMsg::Mint {
            token_id: token_id.clone(),
            owner: "venus".into(),
            name: name.clone(),
            description: Some(description.clone()),
            image: None,
        };

        let minter = mock_env();
        let info = mock_info(MINTER, &[]);
        execute(deps.as_mut(), minter, info, mint_msg).unwrap();

        // random cannot transfer
        let random = mock_env();
        let info = mock_info("addr0000", &[]);
        let transfer_msg = ExecuteMsg::TransferNft {
            recipient: "random".into(),
            token_id: token_id.clone(),
        };

        let err = execute(deps.as_mut(), random, info, transfer_msg.clone()).unwrap_err();

        match err {
            StdError::GenericErr { .. } => {}
            e => panic!("unexpected error: {}", e),
        }

        // owner can
        let owner = mock_info("venus", &[]);
        let transfer_msg = ExecuteMsg::TransferNft {
            recipient: "random".into(),
            token_id: token_id.clone(),
        };

        let res = execute(deps.as_mut(), mock_env(), owner, transfer_msg.clone()).unwrap();

        assert_eq!(
            res,
            Response::new()
                .add_attribute("action", "transfer_nft")
                .add_attribute("sender", "venus")
                .add_attribute("recipient", "random")
                .add_attribute("token_id", token_id)
        );

        // check owner
        let tokens = query_tokens(deps.as_ref(), Addr::unchecked("venus"), None, None).unwrap();
        assert_eq!(0, tokens.tokens.len());
        let count = query_num_owned(deps.as_ref(), Addr::unchecked("venus")).unwrap();
        assert_eq!(0, count.count);

        let tokens = query_tokens(deps.as_ref(), Addr::unchecked("random"), None, None).unwrap();
        assert_eq!(1, tokens.tokens.len());
        assert_eq!("melt".to_string(), tokens.tokens[0]);
        let count = query_num_owned(deps.as_ref(), Addr::unchecked("random")).unwrap();
        assert_eq!(1, count.count);
    }

    #[test]
    fn sending_nft() {
        let mut deps = mock_dependencies(&[]);
        setup_contract(deps.as_mut());

        // Mint a token
        let token_id = "melt".to_string();
        let name = "Melting power".to_string();
        let description = "Allows the owner to melt anyone looking at him or her".to_string();

        let mint_msg = ExecuteMsg::Mint {
            token_id: token_id.clone(),
            owner: "venus".into(),
            name: name.clone(),
            description: Some(description.clone()),
            image: None,
        };

        let minter = mock_info(MINTER, &[]);
        execute(deps.as_mut(), mock_env(), minter, mint_msg).unwrap();

        // random cannot send

        let msg = to_binary("You now have the melting power").unwrap();
        let target: Addr = Addr::unchecked("another_contract");
        let send_msg = ExecuteMsg::SendNft {
            contract: target.to_string().clone(),
            token_id: token_id.clone(),
            msg: msg.clone(),
        };

        let random = mock_info("addr0000", &[]);
        let err = execute(deps.as_mut(), mock_env(), random, send_msg.clone()).unwrap_err();
        match err {
            StdError::GenericErr { .. } => {}
            e => panic!("unexpected error: {}", e),
        }

        // but owner can
        let owner = mock_info("venus", &[]);
        let res = execute(deps.as_mut(), mock_env(), owner, send_msg).unwrap();

        let payload = Cw721ReceiveMsg {
            sender: "venus".into(),
            token_id: token_id.clone(),
            msg,
        };
        let expected = payload.into_cosmos_msg(target.to_string().clone()).unwrap();
        // ensure expected serializes as we think it should
        match &expected {
            CosmosMsg::Wasm(WasmMsg::Execute { contract_addr, .. }) => {
                assert_eq!(contract_addr, &target)
            }
            m => panic!("Unexpected message type: {:?}", m),
        }

        assert_eq!(
            res,
            Response::new()
                .add_message(expected)
                .add_attribute("action", "send_nft")
                .add_attribute("sender", "venus")
                .add_attribute("recipient", "another_contract")
                .add_attribute("token_id", token_id)
        );

        // check owner
        let tokens = query_tokens(deps.as_ref(), Addr::unchecked("venus"), None, None).unwrap();
        assert_eq!(0, tokens.tokens.len());
        let count = query_num_owned(deps.as_ref(), Addr::unchecked("venus")).unwrap();
        assert_eq!(0, count.count);

        let tokens = query_tokens(
            deps.as_ref(),
            Addr::unchecked("another_contract"),
            None,
            None,
        )
        .unwrap();
        assert_eq!(1, tokens.tokens.len());
        assert_eq!("melt".to_string(), tokens.tokens[0]);
        let count = query_num_owned(deps.as_ref(), Addr::unchecked("another_contract")).unwrap();
        assert_eq!(1, count.count);
    }

    #[test]
    fn approving_revoking() {
        let mut deps = mock_dependencies(&[]);
        setup_contract(deps.as_mut());

        // Mint a token
        let token_id = "grow".to_string();
        let name = "Growing power".to_string();
        let description = "Allows the owner to grow anything".to_string();

        let mint_msg = ExecuteMsg::Mint {
            token_id: token_id.clone(),
            owner: "demeter".into(),
            name: name.clone(),
            description: Some(description.clone()),
            image: None,
        };

        let minter = mock_info(MINTER, &[]);
        execute(deps.as_mut(), mock_env(), minter, mint_msg).unwrap();

        // Give random transferring power
        let approve_msg = ExecuteMsg::Approve {
            spender: "random".into(),
            token_id: token_id.clone(),
            expires: None,
        };
        let owner = mock_info("demeter", &[]);
        let res = execute(deps.as_mut(), mock_env(), owner, approve_msg).unwrap();
        assert_eq!(
            res,
            Response::new()
                .add_attribute("action", "approve")
                .add_attribute("sender", "demeter")
                .add_attribute("spender", "random")
                .add_attribute("token_id", token_id.clone())
        );

        // random can now transfer
        let random = mock_info("random", &[]);
        let transfer_msg = ExecuteMsg::TransferNft {
            recipient: "person".into(),
            token_id: token_id.clone(),
        };
        execute(deps.as_mut(), mock_env(), random, transfer_msg).unwrap();

        // Approvals are removed / cleared
        let query_msg = QueryMsg::OwnerOf {
            token_id: token_id.clone(),
        };
        let res: OwnerOfResponse =
            from_binary(&query(deps.as_ref(), mock_env(), query_msg.clone()).unwrap()).unwrap();
        assert_eq!(
            res,
            OwnerOfResponse {
                owner: "person".into(),
                approvals: vec![],
            }
        );

        // Approve, revoke, and check for empty, to test revoke
        let approve_msg = ExecuteMsg::Approve {
            spender: "random".into(),
            token_id: token_id.clone(),
            expires: None,
        };
        let owner = mock_env();
        let info = mock_info("person", &[]);
        execute(deps.as_mut(), owner.clone(), info.clone(), approve_msg).unwrap();

        let revoke_msg = ExecuteMsg::Revoke {
            spender: "random".into(),
            token_id: token_id.clone(),
        };
        execute(deps.as_mut(), owner, info, revoke_msg).unwrap();

        // Approvals are now removed / cleared
        let res: OwnerOfResponse = from_binary(&query(deps.as_ref(), mock_env(), query_msg).unwrap()).unwrap();
        assert_eq!(
            res,
            OwnerOfResponse {
                owner: "person".into(),
                approvals: vec![],
            }
        );
    }

    #[test]
    fn approving_all_revoking_all() {
        let mut deps = mock_dependencies(&[]);
        setup_contract(deps.as_mut());

        // Mint a couple tokens (from the same owner)
        let token_id1 = "grow1".to_string();
        let name1 = "Growing power".to_string();
        let description1 = "Allows the owner the power to grow anything".to_string();
        let token_id2 = "grow2".to_string();
        let name2 = "More growing power".to_string();
        let description2 = "Allows the owner the power to grow anything even faster".to_string();

        let mint_msg1 = ExecuteMsg::Mint {
            token_id: token_id1.clone(),
            owner: "demeter".into(),
            name: name1.clone(),
            description: Some(description1.clone()),
            image: None,
        };

        let minter = mock_env();
        let info = mock_info(MINTER, &[]);
        execute(deps.as_mut(), minter.clone(), info.clone(), mint_msg1).unwrap();

        let mint_msg2 = ExecuteMsg::Mint {
            token_id: token_id2.clone(),
            owner: "demeter".into(),
            name: name2.clone(),
            description: Some(description2.clone()),
            image: None,
        };

        // let info = mock_info("addr0000", &[]);
        execute(deps.as_mut(), minter, info, mint_msg2).unwrap();

        // paginate the token_ids
        let tokens = query_all_tokens(deps.as_ref(), None, Some(1)).unwrap();
        assert_eq!(1, tokens.tokens.len());
        assert_eq!(vec![token_id1.clone()], tokens.tokens);
        let tokens = query_all_tokens(deps.as_ref(), Some(token_id1.clone()), Some(3)).unwrap();
        assert_eq!(1, tokens.tokens.len());
        assert_eq!(vec![token_id2.clone()], tokens.tokens);

        // demeter gives random full (operator) power over her tokens
        let approve_all_msg = ExecuteMsg::ApproveAll {
            operator: "random".into(),
            expires: None,
        };
        let owner = mock_env();
        let info = mock_info("demeter", &[]);
        let res = execute(deps.as_mut(), owner, info, approve_all_msg).unwrap();
        assert_eq!(
            res,
            Response::new()
                .add_attribute("action", "approve_all")
                .add_attribute("sender", "demeter")
                .add_attribute("operator", "random")
        );

        // random can now transfer
        let random = mock_env();
        let info = mock_info("random", &[]);
        let transfer_msg = ExecuteMsg::TransferNft {
            recipient: "person".into(),
            token_id: token_id1.clone(),
        };
        execute(deps.as_mut(), random.clone(), info.clone(), transfer_msg).unwrap();

        // random can now send
        let inner_msg = WasmMsg::Execute {
            contract_addr: "another_contract".into(),
            msg: to_binary("You now also have the growing power").unwrap(),
            funds: vec![],
        };
        let msg: CosmosMsg = CosmosMsg::Wasm(inner_msg);

        let send_msg = ExecuteMsg::SendNft {
            contract: "another_contract".into(),
            token_id: token_id2.clone(),
            msg: to_binary(&msg).unwrap(),
        };
        execute(deps.as_mut(), random, info, send_msg).unwrap();

        // Approve_all, revoke_all, and check for empty, to test revoke_all
        let approve_all_msg = ExecuteMsg::ApproveAll {
            operator: "operator".into(),
            expires: None,
        };
        // person is now the owner of the tokens
        let owner = mock_env();
        let info = mock_info("person", &[]);
        execute(deps.as_mut(), owner.clone(), info.clone(), approve_all_msg).unwrap();

        let res =
            query_all_approvals(deps.as_ref(), Addr::unchecked("person"), None, None).unwrap();
        assert_eq!(
            res,
            ApprovedForAllResponse {
                operators: vec![cw721::Approval {
                    spender: "operator".into(),
                    expires: Expiration::Never {}
                }]
            }
        );

        // second approval
        let buddy_expires = Expiration::AtHeight(1234567);
        let approve_all_msg = ExecuteMsg::ApproveAll {
            operator: "buddy".into(),
            expires: Some(buddy_expires),
        };
        let owner = mock_env();
        let info = mock_info("person",&[]);
        execute(deps.as_mut(), owner.clone(), info.clone(), approve_all_msg).unwrap();

        // and paginate queries.
        let res = query_all_approvals(deps.as_ref(), Addr::unchecked("person"), None, Some(2)).unwrap();
        assert_eq!(
            res,
            ApprovedForAllResponse {
                operators: vec![cw721::Approval {
                    spender: "operator".into(),
                    expires: Expiration::Never {},
                }, cw721::Approval {
                    spender: "buddy".into(),
                    expires: buddy_expires,
                }]
            }
        );
        // issue, paging is not work for query approval & operator
        /*
        let res =
            query_all_approvals(deps.as_ref(), Addr::unchecked("person"), Some("buddy".into()), Some(2)).unwrap();
        assert_eq!(
            res,
            ApprovedForAllResponse {
                operators: vec![cw721::Approval {
                    spender: "operator".into(),
                    expires: Expiration::Never {}
                }]
            }
        );
        */
        let revoke_all_msg = ExecuteMsg::RevokeAll {
            operator: "operator".into(),
        };
        execute(deps.as_mut(), owner, info, revoke_all_msg).unwrap();

        // Approvals are removed / cleared without affecting others
        let res = query_all_approvals(deps.as_ref(), Addr::unchecked("person"), None, None).unwrap();
        assert_eq!(
            res,
            ApprovedForAllResponse {
                operators: vec![cw721::Approval {
                    spender: "buddy".into(),
                    expires: buddy_expires,
                }]
            }
        );
    }

    #[test]
    fn convert_cw721_metadata() {
        let deps = mock_dependencies(&[]);
        let info:TokenInfo = TokenInfo {
            owner: deps.api.addr_canonicalize("degen").unwrap(),
            approvals: vec![],
            name: "Terranauts #1".to_string(),
            description: "".to_string(),
            image: Some("ipfs://Qmcw9FebSs3BFE3BzmFcWnpeUUnQFou5rXLnhPbsFRm51U".to_string())
        };
        let additional:TokenAdditionalInfo = TokenAdditionalInfo {
            uri: None,
            creator: None,
            royalty_percent_fee: None,
            metadata: Some("[{\"name\":\"Background\",\"value\":\"Purple Starfield\"},{\"name\":\"Eyes\",\"value\":\"Red Eyes\"},{\"name\":\"Identity\",\"value\":null}]".to_string())
        };
        let nft_info = convert_cw721(deps.as_ref(), info.clone(), additional.clone()).unwrap();
        assert_eq!(NftInfoResponse {
            token_uri: None,
            extension: Some(Metadata {
                image: Some("ipfs://Qmcw9FebSs3BFE3BzmFcWnpeUUnQFou5rXLnhPbsFRm51U".to_string()),
                image_data: None,
                external_url: None,
                description: Some("".to_string()),
                name: Some(info.name),
                attributes: Some(vec![
                    Trait {
                        display_type: None,
                        trait_type: "Background".to_string(),
                        value: "Purple Starfield".to_string()
                    }, 
                    Trait {
                        display_type: None,
                        trait_type: "Eyes".to_string(),
                        value: "Red Eyes".to_string()
                    },
                    Trait {
                        display_type: None,
                        trait_type: "Identity".to_string(),
                        value: "".to_string()
                    }
                ]),
                background_color: None,
                animation_url: None,
                youtube_url: None
            })
        }, nft_info);
    }
}