use http_body_util::BodyExt;
use hyper::{Request, body::{Incoming, Buf}, Response};

use crate::{BoxBody, GenericError};

pub async fn login(req: Request<Incoming>) -> Result<Response<BoxBody>, GenericError> {
    // Aggregate the body...
    let whole_body = req.collect().await?.aggregate();
    // Decode as JSON...
    let data: serde_json::Value = serde_json::from_reader(whole_body.reader())?;
    let username = &data["username"];
    let password = &data["password"];
    

    todo!()
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
