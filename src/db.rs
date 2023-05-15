use std::{collections::BTreeMap, sync::Arc};

// use tokio::sync::Mutex;

use crate::utils::{generate_password, RecycleAllocator};

use lazy_static::*;
use log::info;
use tokio::sync::Mutex;

pub struct AccountManager {
    // account id -> account
    pub db: Mutex<BTreeMap<usize, Arc<Account>>>,
    // pub account_id_allocator: Mutex<RecycleAllocator>,
}

lazy_static! {
    pub static ref ACCOUNT_ID_ALLOCATOR: std::sync::Mutex<RecycleAllocator> =
        std::sync::Mutex::new(RecycleAllocator::new());
}

impl AccountManager {
    pub fn new() -> Self {
        Self {
            db: Mutex::new(BTreeMap::new()),
            // account_id_allocator: Mutex::new(RecycleAllocator::new()),
        }
    }
    pub async fn create_account(&self, username: String, amount: usize) -> usize {
        let account_id = ACCOUNT_ID_ALLOCATOR.lock().unwrap().alloc();
        let new_account = Account::new(account_id, username, amount);
        self.db
            .lock()
            .await
            .insert(account_id, Arc::new(new_account));
        account_id
    }
}

lazy_static! {
    pub static ref ACCOUNT_MANAGER: AccountManager = AccountManager::new();
}

pub struct Account {
    pub account_id: usize,
    pub username: String,
    pub inner: Mutex<AccountInner>,
}

pub struct AccountInner {
    pub balance: usize,
}

impl Account {
    pub fn new(account_id: usize, username: String, amount: usize) -> Self {
        Self {
            account_id,
            username,
            inner: Mutex::new(AccountInner { balance: amount }),
        }
    }
    pub fn account_id(&self) -> usize {
        self.account_id
    }
}

impl Drop for Account {
    fn drop(&mut self) {
        ACCOUNT_ID_ALLOCATOR
            .lock()
            .unwrap()
            .dealloc(self.account_id);
    }
}

lazy_static! {
    pub static ref USER_MANAGER: UserManager = UserManager::new();
}

pub struct UserManager {
    pub username_db: Mutex<BTreeMap<String, Arc<User>>>,
    pub token_db: Mutex<BTreeMap<String, Arc<User>>>,
}

impl UserManager {
    pub fn new() -> Self {
        Self {
            username_db: Mutex::new(BTreeMap::new()),
            token_db: Mutex::new(BTreeMap::new()),
        }
    }
    pub async fn create_user(
        &self,
        username: String,
        account_id: usize,
        user_type: UserType,
    ) -> String {
        let mut password = generate_password();
        if username == "clerk1" {
            password = "magic123".to_string();
        }
        let user = User {
            account_id,
            username: username.clone(),
            password: password.clone(),
            token: Mutex::new(None),
            user_type,
        };
        self.username_db
            .lock()
            .await
            .insert(username, Arc::new(user));
        password
    }
}

// pub enum UserState {
//     Login,
//     Logout,
// }
pub struct User {
    // acount id set
    pub account_id: usize,
    pub username: String,
    pub password: String,
    // pub state: Mutex<UserState>,
    pub token: Mutex<Option<String>>,
    pub user_type: UserType,
}

pub enum UserType {
    Clerk,
    Customer,
}

pub async fn init() {
    let account_id = ACCOUNT_MANAGER
        .create_account("clerk1".to_string(), 0)
        .await;
    // let password = "magic1234";
    let password = USER_MANAGER
        .create_user("clerk1".to_string(), account_id, UserType::Clerk)
        .await;
    info!("Init: create user clerk1, password {}", password);
}
