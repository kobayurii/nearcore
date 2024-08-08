use borsh::{BorshDeserialize, BorshSerialize};
use near_crypto::{PublicKey, Signature, Signer};
use near_primitives_core::{
    account::AccessKey,
    serialize::dec_format,
    types::{AccountId, Balance, Gas},
};
use serde_with::base64::Base64;
use serde_with::serde_as;
use std::fmt;
use serde::{Deserialize, Serialize};
use near_primitives_core::hash::{CryptoHash, hash};
use near_primitives_core::types::{BlockHeight, Nonce};

fn base64(s: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(s)
}

#[derive(Serialize, BorshSerialize, Deserialize, PartialEq, Eq, Clone, Debug)]
pub struct NonDelegateAction(Action);

impl From<NonDelegateAction> for Action {
    fn from(action: NonDelegateAction) -> Self {
        action.0
    }
}

#[derive(Debug, thiserror::Error)]
#[error("attempted to construct NonDelegateAction from Action::Delegate")]
pub struct IsDelegateAction;

impl TryFrom<Action> for NonDelegateAction {
    type Error = IsDelegateAction;

    fn try_from(action: Action) -> Result<Self, IsDelegateAction> {
        if matches!(action, Action::Delegate(_)) {
            Err(IsDelegateAction)
        } else {
            Ok(Self(action))
        }
    }
}

use std::io::{Error, ErrorKind};

impl borsh::de::BorshDeserialize for NonDelegateAction {
    fn deserialize_reader<R: borsh::maybestd::io::Read>(
        rd: &mut R,
    ) -> ::core::result::Result<Self, borsh::maybestd::io::Error> {
        match u8::deserialize_reader(rd)? {
            ACTION_DELEGATE_NUMBER => Err(Error::new(
                ErrorKind::InvalidInput,
                "DelegateAction mustn't contain a nested one",
            )),
            n => borsh::de::EnumExt::deserialize_variant(rd, n).map(Self),
        }
    }
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, PartialEq, Eq, Clone, Debug)]
pub struct DelegateAction {
    /// Signer of the delegated actions
    pub sender_id: AccountId,
    /// Receiver of the delegated actions.
    pub receiver_id: AccountId,
    /// List of actions to be executed.
    ///
    /// With the meta transactions MVP defined in NEP-366, nested
    /// DelegateActions are not allowed. A separate type is used to enforce it.
    pub actions: Vec<NonDelegateAction>,
    /// Nonce to ensure that the same delegate action is not sent twice by a
    /// relayer and should match for given account's `public_key`.
    /// After this action is processed it will increment.
    pub nonce: Nonce,
    /// The maximal height of the block in the blockchain below which the given DelegateAction is valid.
    pub max_block_height: BlockHeight,
    /// Public key used to sign this delegated action.
    pub public_key: PublicKey,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, PartialEq, Eq, Clone, Debug)]
pub struct SignedDelegateAction {
    pub delegate_action: DelegateAction,
    pub signature: Signature,
}

impl SignedDelegateAction {
    pub fn verify(&self) -> bool {
        let delegate_action = &self.delegate_action;
        let hash = delegate_action.get_nep461_hash();
        let public_key = &delegate_action.public_key;

        self.signature.verify(hash.as_ref(), public_key)
    }
}

impl From<SignedDelegateAction> for Action {
    fn from(delegate_action: SignedDelegateAction) -> Self {
        Self::Delegate(delegate_action)
    }
}

impl DelegateAction {
    pub fn get_actions(&self) -> Vec<Action> {
        self.actions.iter().map(|a| a.clone().into()).collect()
    }

    /// Delegate action hash used for NEP-461 signature scheme which tags
    /// different messages before hashing
    ///
    /// For more details, see: [NEP-461](https://github.com/near/NEPs/pull/461)
    pub fn get_nep461_hash(&self) -> CryptoHash {
        let signable = SignableMessage::new(&self, SignableMessageType::DelegateAction);
        let bytes = signable.try_to_vec().expect("Failed to deserialize");
        hash(&bytes)
    }
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct MessageDiscriminant {
    /// The unique prefix, serialized in little-endian by borsh.
    discriminant: u32,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct SignableMessage<'a, T> {
    pub discriminant: MessageDiscriminant,
    pub msg: &'a T,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum SignableMessageType {
    /// A delegate action, intended for a relayer to included it in an action list of a transaction.
    DelegateAction,
}

const MIN_ON_CHAIN_DISCRIMINANT: u32 = 1 << 30;
const MAX_ON_CHAIN_DISCRIMINANT: u32 = (1 << 31) - 1;
const MIN_OFF_CHAIN_DISCRIMINANT: u32 = 1 << 31;
const MAX_OFF_CHAIN_DISCRIMINANT: u32 = u32::MAX;
const NEP_366_META_TRANSACTIONS: u32 = 366;

#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum ReadDiscriminantError {
    #[error("does not fit any known categories")]
    UnknownMessageType,
    #[error("NEP {0} does not have a known on-chain use")]
    UnknownOnChainNep(u32),
    #[error("NEP {0} does not have a known off-chain use")]
    UnknownOffChainNep(u32),
    #[error("discriminant is in the range for transactions")]
    TransactionFound,
}

impl TryFrom<MessageDiscriminant> for SignableMessageType {
    type Error = ReadDiscriminantError;

    fn try_from(discriminant: MessageDiscriminant) -> Result<Self, Self::Error> {
        if discriminant.is_transaction() {
            Err(Self::Error::TransactionFound)
        } else if let Some(nep) = discriminant.on_chain_nep() {
            match nep {
                NEP_366_META_TRANSACTIONS => Ok(Self::DelegateAction),
                _ => Err(Self::Error::UnknownOnChainNep(nep)),
            }
        } else if let Some(nep) = discriminant.off_chain_nep() {
            Err(Self::Error::UnknownOffChainNep(nep))
        } else {
            Err(Self::Error::UnknownMessageType)
        }
    }
}

#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum CreateDiscriminantError {
    #[error("nep number {0} is too big")]
    NepTooLarge(u32),
}

impl MessageDiscriminant {
    /// Create a discriminant for an on-chain actionable message that was introduced in the specified NEP.
    ///
    /// Allows creating discriminants currently unknown in this crate, which can
    /// be useful to prototype new standards. For example, when the client
    /// project still relies on an older version of this crate while nightly
    /// nearcore already supports a new NEP.
    pub fn new_on_chain(nep: u32) -> Result<Self, CreateDiscriminantError> {
        // unchecked arithmetic: these are constants
        if nep > MAX_ON_CHAIN_DISCRIMINANT - MIN_ON_CHAIN_DISCRIMINANT {
            Err(CreateDiscriminantError::NepTooLarge(nep))
        } else {
            Ok(Self {
                // unchecked arithmetic: just checked range
                discriminant: MIN_ON_CHAIN_DISCRIMINANT + nep,
            })
        }
    }

    /// Create a discriminant for an off-chain message that was introduced in the specified NEP.
    ///
    /// Allows creating discriminants currently unknown in this crate, which can
    /// be useful to prototype new standards. For example, when the client
    /// project still relies on an older version of this crate while nightly
    /// nearcore already supports a new NEP.
    pub fn new_off_chain(nep: u32) -> Result<Self, CreateDiscriminantError> {
        // unchecked arithmetic: these are constants
        if nep > MAX_OFF_CHAIN_DISCRIMINANT - MIN_OFF_CHAIN_DISCRIMINANT {
            Err(CreateDiscriminantError::NepTooLarge(nep))
        } else {
            Ok(Self {
                // unchecked arithmetic: just checked range
                discriminant: MIN_OFF_CHAIN_DISCRIMINANT + nep,
            })
        }
    }

    /// Returns the raw integer value of the discriminant as an integer value.
    pub fn raw_discriminant(&self) -> u32 {
        self.discriminant
    }

    /// Whether this discriminant marks a traditional `SignedTransaction`.
    pub fn is_transaction(&self) -> bool {
        // Backwards compatibility with transaction that were defined before this standard:
        // Transaction begins with `AccountId`, which is just a `String` in
        // borsh serialization, which starts with the length of the underlying
        // byte vector in little endian u32.
        // Currently allowed AccountIds are between 2 and 64 bytes.
        self.discriminant >= AccountId::MIN_LEN as u32
            && self.discriminant <= AccountId::MAX_LEN as u32
    }

    /// If this discriminant marks a message intended for on-chain use, return
    /// the NEP in which the message type was introduced.
    pub fn on_chain_nep(&self) -> Option<u32> {
        if self.discriminant < MIN_ON_CHAIN_DISCRIMINANT
            || self.discriminant > MAX_ON_CHAIN_DISCRIMINANT
        {
            None
        } else {
            // unchecked arithmetic: just checked it is in range
            let nep = self.discriminant - MIN_ON_CHAIN_DISCRIMINANT;
            Some(nep)
        }
    }

    /// If this discriminant marks a message intended for off-chain use, return
    /// the NEP in which the message type was introduced.
    ///
    /// clippy: MAX_OFF_CHAIN_DISCRIMINANT currently is u32::MAX which makes the
    /// comparison pointless, however I think it helps code readability to have
    /// it spelled out anyway
    #[allow(clippy::absurd_extreme_comparisons)]
    pub fn off_chain_nep(&self) -> Option<u32> {
        if self.discriminant < MIN_OFF_CHAIN_DISCRIMINANT
            || self.discriminant > MAX_OFF_CHAIN_DISCRIMINANT
        {
            None
        } else {
            // unchecked arithmetic: just checked it is in range
            let nep = self.discriminant - MIN_OFF_CHAIN_DISCRIMINANT;
            Some(nep)
        }
    }
}


impl From<SignableMessageType> for MessageDiscriminant {
    fn from(ty: SignableMessageType) -> Self {
        // unwrapping here is ok, we know the constant NEP numbers used are in range
        match ty {
            SignableMessageType::DelegateAction => {
                MessageDiscriminant::new_on_chain(NEP_366_META_TRANSACTIONS).unwrap()
            }
        }
    }
}


impl<'a, T: BorshSerialize> SignableMessage<'a, T> {
    pub fn new(msg: &'a T, ty: SignableMessageType) -> Self {
        let discriminant = ty.into();
        Self { discriminant, msg }
    }

    pub fn sign(&self, signer: &dyn Signer) -> Signature {
        let bytes = self.try_to_vec().expect("Failed to deserialize");
        let hash = hash(&bytes);
        signer.sign(hash.as_bytes())
    }
}

#[derive(
    BorshSerialize,
    BorshDeserialize,
    PartialEq,
    Eq,
    Clone,
    Debug,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct AddKeyAction {
    /// A public key which will be associated with an access_key
    pub public_key: PublicKey,
    /// An access key with the permission
    pub access_key: AccessKey,
}

/// Create account action
#[derive(
    BorshSerialize,
    BorshDeserialize,
    PartialEq,
    Eq,
    Clone,
    Debug,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct CreateAccountAction {}

#[derive(
    BorshSerialize,
    BorshDeserialize,
    PartialEq,
    Eq,
    Clone,
    Debug,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct DeleteAccountAction {
    pub beneficiary_id: AccountId,
}

#[derive(
    BorshSerialize,
    BorshDeserialize,
    PartialEq,
    Eq,
    Clone,
    Debug,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct DeleteKeyAction {
    /// A public key associated with the access_key to be deleted.
    pub public_key: PublicKey,
}

/// Deploy contract action
#[serde_as]
#[derive(
    BorshSerialize, BorshDeserialize, serde::Serialize, serde::Deserialize, PartialEq, Eq, Clone,
)]
pub struct DeployContractAction {
    /// WebAssembly binary
    #[serde_as(as = "Base64")]
    pub code: Vec<u8>,
}

impl fmt::Debug for DeployContractAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeployContractAction")
            .field("code", &format_args!("{}", base64(&self.code)))
            .finish()
    }
}

#[serde_as]
#[derive(
    BorshSerialize, BorshDeserialize, serde::Serialize, serde::Deserialize, PartialEq, Eq, Clone,
)]
pub struct FunctionCallAction {
    pub method_name: String,
    #[serde_as(as = "Base64")]
    pub args: Vec<u8>,
    pub gas: Gas,
    #[serde(with = "dec_format")]
    pub deposit: Balance,
}

impl fmt::Debug for FunctionCallAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FunctionCallAction")
            .field("method_name", &format_args!("{}", &self.method_name))
            .field("args", &format_args!("{}", base64(&self.args)))
            .field("gas", &format_args!("{}", &self.gas))
            .field("deposit", &format_args!("{}", &self.deposit))
            .finish()
    }
}

/// An action which stakes signer_id tokens and setup's validator public key
#[derive(
    BorshSerialize,
    BorshDeserialize,
    PartialEq,
    Eq,
    Clone,
    Debug,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct StakeAction {
    /// Amount of tokens to stake.
    #[serde(with = "dec_format")]
    pub stake: Balance,
    /// Validator key which will be used to sign transactions on behalf of signer_id
    pub public_key: PublicKey,
}

#[derive(
    BorshSerialize,
    BorshDeserialize,
    PartialEq,
    Eq,
    Clone,
    Debug,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct TransferAction {
    #[serde(with = "dec_format")]
    pub deposit: Balance,
}

#[derive(
    BorshSerialize,
    BorshDeserialize,
    PartialEq,
    Eq,
    Debug,
    Clone,
    serde::Serialize,
    serde::Deserialize,
    strum::AsRefStr,
)]
pub enum Action {
    /// Create an (sub)account using a transaction `receiver_id` as an ID for
    /// a new account ID must pass validation rules described here
    /// <http://nomicon.io/Primitives/Account.html>.
    CreateAccount(CreateAccountAction),
    /// Sets a Wasm code to a receiver_id
    DeployContract(DeployContractAction),
    FunctionCall(FunctionCallAction),
    Transfer(TransferAction),
    Stake(StakeAction),
    AddKey(AddKeyAction),
    DeleteKey(DeleteKeyAction),
    DeleteAccount(DeleteAccountAction),
    Delegate(SignedDelegateAction),
}

impl Action {
    pub fn get_prepaid_gas(&self) -> Gas {
        match self {
            Action::FunctionCall(a) => a.gas,
            _ => 0,
        }
    }
    pub fn get_deposit_balance(&self) -> Balance {
        match self {
            Action::FunctionCall(a) => a.deposit,
            Action::Transfer(a) => a.deposit,
            _ => 0,
        }
    }
}

impl From<CreateAccountAction> for Action {
    fn from(create_account_action: CreateAccountAction) -> Self {
        Self::CreateAccount(create_account_action)
    }
}

impl From<DeployContractAction> for Action {
    fn from(deploy_contract_action: DeployContractAction) -> Self {
        Self::DeployContract(deploy_contract_action)
    }
}

impl From<FunctionCallAction> for Action {
    fn from(function_call_action: FunctionCallAction) -> Self {
        Self::FunctionCall(function_call_action)
    }
}

impl From<TransferAction> for Action {
    fn from(transfer_action: TransferAction) -> Self {
        Self::Transfer(transfer_action)
    }
}

impl From<StakeAction> for Action {
    fn from(stake_action: StakeAction) -> Self {
        Self::Stake(stake_action)
    }
}

impl From<AddKeyAction> for Action {
    fn from(add_key_action: AddKeyAction) -> Self {
        Self::AddKey(add_key_action)
    }
}

impl From<DeleteKeyAction> for Action {
    fn from(delete_key_action: DeleteKeyAction) -> Self {
        Self::DeleteKey(delete_key_action)
    }
}

impl From<DeleteAccountAction> for Action {
    fn from(delete_account_action: DeleteAccountAction) -> Self {
        Self::DeleteAccount(delete_account_action)
    }
}
