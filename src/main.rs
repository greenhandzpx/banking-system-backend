use std::net::SocketAddr;

use http_body_util::{BodyExt, Empty};
use hyper::{
    body::{Bytes, Incoming},
    server::conn::http1,
    service::service_fn,
    Method, Request, Response, StatusCode,
};
use log::info;
use operations::{balance, delete_account, login, open_account, transfer};
use tokio::net::TcpListener;

use crate::operations::preprocess;

mod db;
mod error;
mod message;
mod operations;
mod transaction;
mod utils;

type GenericError = Box<dyn std::error::Error + Send + Sync>;
pub type BoxBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

fn empty() -> BoxBody {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

async fn handle_request(req: Request<Incoming>) -> Result<Response<BoxBody>, GenericError> {
    info!("Receive a request {}, method {}", req.uri().path(), req.method());
    match (req.method(), req.uri().path()) {
        // (&Method::GET, "/") | (&Method::GET, "/index.html") => Ok(Response::new(full(INDEX))),
        (&Method::OPTIONS, _) => preprocess(req).await,
        (&Method::POST, "/login") => login(req).await,
        (&Method::POST, "/open_account") => open_account(req).await,
        (&Method::POST, "/delete_account") => delete_account(req).await,
        (&Method::POST, "/balance") => balance(req).await,
        (&Method::POST, "/transfer") => transfer(req).await,
        // (&Method::POST, "/") => api_post_response(req).await,
        // (&Method::GET, "/json_api") => api_get_response().await,
        _ => {
            // Return 404 not found response.
            let mut not_found = Response::new(empty());
            *not_found.status_mut() = StatusCode::NOT_FOUND;
            Ok(not_found)
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    env_logger::init();


    // let addr = SocketAddr::from(([127, 0, 0, 1], 12345));
    let addr = SocketAddr::from(([10, 251, 176, 190], 12345));

    // We create a TcpListener and bind it to 127.0.0.1:3000
    let listener = TcpListener::bind(addr).await?;

    info!("start server");

    db::init().await;

    // We start a loop to continuously accept incoming connections
    loop {
        let (stream, _) = listener.accept().await?;

        info!("Accpet a client");

        // Spawn a tokio task to serve multiple connections concurrently
        tokio::task::spawn(async move {
            // Finally, we bind the incoming connection to our `hello` service
            if let Err(err) = http1::Builder::new()
                // `service_fn` converts our function in a `Service`
                .serve_connection(stream, service_fn(handle_request))
                .await
            {
                println!("Error serving connection: {:?}", err);
            }
        });
    }
}
