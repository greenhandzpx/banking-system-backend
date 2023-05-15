use http_body_util::BodyExt;
use hyper::{
    body::{Buf, Incoming},
    header::AUTHORIZATION,
    header,
    Request, Response, StatusCode,
};
use log::info;

use crate::{
    db::{UserType, ACCOUNT_MANAGER, USER_MANAGER},
    message::{
        BalanceArgs, BalanceReply, DeleteAccountArgs, DeleteAccountReply, LoginArgs, LoginReply,
        OpenAccountArgs, OpenAccountReply, TransferArgs, TransferReply, LOGIN_STATE,
    },
    transaction::Transaction,
    utils::{full, generate_token},
    BoxBody, GenericError,
};

pub async fn login(req: Request<Incoming>) -> Result<Response<BoxBody>, GenericError> {
    let mut resp = LoginReply {
        token: "".to_string(),
        state: "".to_string(),
    };

    let headers = req.headers();

    if let Some(token) = headers.get(AUTHORIZATION) {
        let token = token.to_str()?;
        if let Some(user) = USER_MANAGER.token_db.lock().await.get(token) {
            info!("User already login!, username {}", user.username);
            // The user has already logined
            resp = LoginReply {
                token: token.to_string(),
                state: LOGIN_STATE[2].to_string(),
            };
            let ret_json = serde_json::to_string(&resp)?;
            let response = Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .body(full(ret_json))?;
            return Ok(response);
        }
    }

    // Aggregate the body...
    let whole_body = req.collect().await?.aggregate();
    // Decode as JSON...
    let user_info: LoginArgs = serde_json::from_reader(whole_body.reader())?;
    let username = user_info.username;
    let password = user_info.password;

    if let Some(user) = USER_MANAGER.username_db.lock().await.get(&username) {
        if user.password != password {
            info!("Invalid password for user {}", username);
            resp = LoginReply {
                token: "".to_string(),
                state: LOGIN_STATE[1].to_string(),
            };
        } else {
            if let Some(token) = user.token.lock().await.as_ref() {
                info!("No need to generate a new token for user {}", user.username);
                resp = LoginReply {
                    token: token.clone(),
                    state: LOGIN_STATE[1].to_string(),
                };
            } else {
                info!("Generate a new token for user {}", user.username);
                let token = generate_token();
                resp = LoginReply {
                    token: token.clone(),
                    state: LOGIN_STATE[1].to_string(),
                };
                *user.token.lock().await = Some(token.clone());
                USER_MANAGER
                    .token_db
                    .lock()
                    .await
                    .insert(token, user.clone());
            }
        }
    } else {
        info!("No such user {}", username);
        resp = LoginReply {
            token: "".to_string(),
            state: LOGIN_STATE[1].to_string(),
        };
    }

    let ret_json = serde_json::to_string(&resp)?;
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(full(ret_json))?;
    return Ok(response);
}

pub async fn open_account(req: Request<Incoming>) -> Result<Response<BoxBody>, GenericError> {
    let mut resp = OpenAccountReply {
        password: "".to_string(),
        account_id: 0,
        state: "success".to_string(),
    };

    let headers = req.headers();

    if let Some(token) = headers.get(AUTHORIZATION) {
        let token = token.to_str()?;
        if let Some(user) = USER_MANAGER.token_db.lock().await.get(token) {
            match user.user_type {
                UserType::Clerk => {
                    // Aggregate the body...
                    let whole_body = req.collect().await?.aggregate();
                    // Decode as JSON...
                    let open_account_args: OpenAccountArgs =
                        serde_json::from_reader(whole_body.reader())?;

                    if USER_MANAGER
                        .username_db
                        .lock()
                        .await
                        .contains_key(&open_account_args.username)
                    {
                        info!("Username {} already exists", open_account_args.username);
                        resp.state = "fail".to_string();
                    } else {
                        let account_id = ACCOUNT_MANAGER
                            .create_account(
                                open_account_args.username.clone(),
                                open_account_args.amount,
                            )
                            .await;
                        let password = USER_MANAGER
                            .create_user(open_account_args.username, account_id, UserType::Customer)
                            .await;
                        resp.account_id = account_id;
                        resp.password = password;
                        info!("Open account {} success", resp.account_id);
                    }
                }
                UserType::Customer => {
                    info!(
                        "Invalid open_account op for customer user {}",
                        user.username
                    );
                    resp.state = "fail".to_string();
                }
            }
        } else {
            info!("Invalid token for open_account op");
            resp.state = "fail".to_string();
        }
    } else {
        info!("No token for open_account op");
        resp.state = "fail".to_string();
    }

    let ret_json = serde_json::to_string(&resp)?;
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(full(ret_json))?;
    return Ok(response);
}

pub async fn delete_account(req: Request<Incoming>) -> Result<Response<BoxBody>, GenericError> {
    let mut resp = DeleteAccountReply {
        state: "success".to_string(),
    };

    let headers = req.headers();

    if let Some(token) = headers.get(AUTHORIZATION) {
        let token = token.to_str()?;
        if let Some(user) = USER_MANAGER.token_db.lock().await.get(token) {
            match user.user_type {
                UserType::Clerk => {
                    // Aggregate the body...
                    let whole_body = req.collect().await?.aggregate();
                    // Decode as JSON...
                    let delete_account_args: DeleteAccountArgs =
                        serde_json::from_reader(whole_body.reader())?;
                    if !ACCOUNT_MANAGER
                        .db
                        .lock()
                        .await
                        .contains_key(&delete_account_args.account_id)
                    {
                        info!("No such account id {}", delete_account_args.account_id);
                        resp.state = "fail".to_string();
                    } else {
                        let account = ACCOUNT_MANAGER
                            .db
                            .lock()
                            .await
                            .get(&delete_account_args.account_id)
                            .cloned()
                            .unwrap();
                        let user = USER_MANAGER
                            .username_db
                            .lock()
                            .await
                            .get(&account.username)
                            .cloned()
                            .unwrap();
                        let username = user.username.clone();
                        // let token = user.token.lock().await();
                        USER_MANAGER.username_db.lock().await.remove(&username);
                        if let Some(token) = user.token.lock().await.as_ref() {
                            USER_MANAGER.token_db.lock().await.remove(token);
                        }
                        ACCOUNT_MANAGER
                            .db
                            .lock()
                            .await
                            .remove(&delete_account_args.account_id);
                        info!("Delete account {} success", delete_account_args.account_id);
                    }
                }
                UserType::Customer => {
                    info!(
                        "Invalid delete_account op for customer user {}",
                        user.username
                    );
                    resp.state = "fail".to_string();
                }
            }
        } else {
            info!("Invalid token for delete_account op");
            resp.state = "fail".to_string();
        }
    } else {
        info!("No token for delete_account op");
        resp.state = "fail".to_string();
    }

    let ret_json = serde_json::to_string(&resp)?;
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(full(ret_json))?;
    return Ok(response);
}

pub async fn balance(req: Request<Incoming>) -> Result<Response<BoxBody>, GenericError> {
    let mut resp = BalanceReply {
        balance: 0,
        state: "".to_string(),
    };

    let headers = req.headers();

    if let Some(token) = headers.get(AUTHORIZATION) {
        let token = token.to_str()?;
        if let Some(user) = USER_MANAGER.token_db.lock().await.get(token) {
            // Aggregate the body...
            let whole_body = req.collect().await?.aggregate();
            // Decode as JSON...
            let balance_args: BalanceArgs = serde_json::from_reader(whole_body.reader())?;

            if user.account_id != balance_args.account_id {
                info!(
                    "Invalid account id {} for user {}",
                    balance_args.account_id, user.username
                );
                resp.state = "fail".to_string();
            } else {
                if let Some(account) = ACCOUNT_MANAGER.db.lock().await.get(&user.account_id) {
                    resp.balance = account.inner.lock().await.balance;
                    resp.state = "success".to_string();
                    info!("Account balance {} of user {}", resp.balance, user.username);
                } else {
                    info!("No account for user {}", user.username);
                    resp.state = "fail".to_string();
                }
            }
        } else {
            info!("Invalid token for balance op");
            resp.state = "fail".to_string();
        }
    } else {
        info!("No token for balance op");
        resp.state = "fail".to_string();
    }

    let ret_json = serde_json::to_string(&resp)?;
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(full(ret_json))?;
    return Ok(response);
}

pub async fn transfer(req: Request<Incoming>) -> Result<Response<BoxBody>, GenericError> {
    let mut resp = TransferReply {
        state: "success".to_string(),
    };

    let headers = req.headers();

    if let Some(token) = headers.get(AUTHORIZATION) {
        let token = token.to_str()?;
        if let Some(user) = USER_MANAGER.token_db.lock().await.get(token) {
            // Aggregate the body...
            let whole_body = req.collect().await?.aggregate();
            // Decode as JSON...
            let transfer_args: TransferArgs = serde_json::from_reader(whole_body.reader())?;

            if user.account_id != transfer_args.src_account_id {
                info!(
                    "Invalid src account id {} for user {}",
                    transfer_args.src_account_id, user.username
                );
                resp.state = "fail".to_string();
            } else {
                if let Some(src) = ACCOUNT_MANAGER
                    .db
                    .lock()
                    .await
                    .get(&transfer_args.src_account_id)
                {
                    if let Some(dst) = ACCOUNT_MANAGER
                        .db
                        .lock()
                        .await
                        .get(&transfer_args.dst_account_id)
                    {
                        let txn = Transaction::new(src.clone(), dst.clone(), transfer_args.amount);
                        if txn.start().await.is_err() {
                            info!("Transfer fail for user {}", user.username);
                            resp.state = "fail".to_string();
                        }
                    } else {
                        info!(
                            "No dst account id {} for user {}",
                            transfer_args.dst_account_id, user.username
                        );
                        resp.state = "fail".to_string();
                    }
                } else {
                    info!(
                        "No src account id {} for user {}",
                        transfer_args.src_account_id, user.username
                    );
                    resp.state = "fail".to_string();
                }
            }
        } else {
            info!("Invalid token for transfer op");
            resp.state = "fail".to_string();
        }
    } else {
        info!("No token for transfer op");
        resp.state = "fail".to_string();
    }
    let ret_json = serde_json::to_string(&resp)?;
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(full(ret_json))?;
    return Ok(response);
}
