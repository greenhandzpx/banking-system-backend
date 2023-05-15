use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct LoginArgs {
    pub username: String,
    pub password: String,
}

pub const LOGIN_STATE: [&str; 3] = ["success", "fail", "already"];
#[derive(Deserialize, Serialize)]
pub struct LoginReply {
    pub token: String,
    /// success
    /// fail
    /// already
    pub state: String,
    pub account_id: usize,
}

#[derive(Deserialize, Serialize)]
pub struct BalanceArgs {
    pub account_id: usize,
}

#[derive(Deserialize, Serialize)]
pub struct BalanceReply {
    pub balance: usize,
    pub state: String,
}

#[derive(Deserialize, Serialize)]
pub struct TransferArgs {
    pub src_account_id: usize,
    pub dst_account_id: usize,
    pub amount: usize,
}

#[derive(Deserialize, Serialize)]
pub struct TransferReply {
    pub state: String,
}

#[derive(Deserialize, Serialize)]
pub struct OpenAccountArgs {
    pub username: String,
    pub amount: usize,
}

#[derive(Deserialize, Serialize)]
pub struct OpenAccountReply {
    pub account_id: usize,
    pub password: String,
    pub state: String,
}

#[derive(Deserialize, Serialize)]
pub struct DeleteAccountArgs {
    pub account_id: usize,
}

#[derive(Deserialize, Serialize)]
pub struct DeleteAccountReply {
    pub state: String,
}
