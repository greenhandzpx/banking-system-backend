use http_body_util::BodyExt;
use hyper::{Request, body::{Incoming, Buf}, Response, header::{CONTENT_LENGTH, self}, header::AUTHORIZATION, StatusCode};
use log::info;

use crate::{BoxBody, GenericError, db::USER_MANAGER, utils::{full, generate_token}};
use serde::{Serialize, Deserialize};

#[derive(Deserialize, Serialize)]
struct UserInfo {
    username: String,
    password: String,
}

const LOGIN_STATE: [&str; 3] = ["success", "fail", "already"];
#[derive(Deserialize, Serialize)]
struct LoginResponse {
    token: String,
    /// success
    /// fail
    /// already
    state: String,
}


pub async fn login(req: Request<Incoming>) -> Result<Response<BoxBody>, GenericError> {

    let mut resp = LoginResponse {
        token: "".to_string(),
        state: "".to_string(),
    };

    let headers = req.headers();

    if let Some(token) = headers.get(AUTHORIZATION) {
        let token = token.to_str()?;
        if let Some(user) = USER_MANAGER.token_db.lock().await.get(token) {
            info!("User already login!, username {}", user.username);
            // The user has already logined
            resp = LoginResponse {
                token: token.to_string(),
                state: LOGIN_STATE[2].to_string(),
            };
            let ret_json =  serde_json::to_string(&resp)?;
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
    let user_info: UserInfo = serde_json::from_reader(whole_body.reader())?;
    let username = user_info.username;
    let password = user_info.password;


    if let Some(user) = USER_MANAGER.username_db.lock().await.get(&username) {
        if user.password != password {
            info!("Invalid password for user {}", username);
            resp = LoginResponse {
                token: "".to_string(),
                state: LOGIN_STATE[1].to_string(),
            };
        } else {
            if let Some(token) = user.token.lock().await.as_ref() {
                info!("No need to generate a new token for user {}", user.username);
                resp = LoginResponse {
                    token: token.clone(),
                    state: LOGIN_STATE[1].to_string(),
                };
            } else {
                info!("Generate a new token for user {}", user.username);
                let token = generate_token();
                resp = LoginResponse {
                    token: token.clone(),
                    state: LOGIN_STATE[1].to_string(),
                };
                *user.token.lock().await = Some(token.clone());
                USER_MANAGER.token_db.lock().await.insert(token, user.clone());
            }
        }
    } else {
        info!("No such user {}", username);
        resp = LoginResponse {
            token: "".to_string(),
            state: LOGIN_STATE[1].to_string(),
        };
    }
    
    let ret_json =  serde_json::to_string(&resp)?;
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(full(ret_json))?;
    return Ok(response);

}

pub async fn open_account(req: Request<Incoming>) -> Result<Response<BoxBody>, GenericError> {
    
    todo!()
}

pub async fn delete_account(req: Request<Incoming>) -> Result<Response<BoxBody>, GenericError> {
    todo!()
}

pub async fn balance(req: Request<Incoming>) -> Result<Response<BoxBody>, GenericError> {
    todo!()
}

pub async fn transfer(req: Request<Incoming>) -> Result<Response<BoxBody>, GenericError> {
    todo!()
}


