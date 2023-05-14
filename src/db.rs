use std::{collections::BTreeMap, sync::Arc};

use tokio::sync::Mutex;

use crate::utils::RecycleAllocator;

use lazy_static::*;

pub struct AccountManager {
    // account id -> account
    db: Mutex<BTreeMap<usize, Arc<Account>>>,
    account_id_allocator: Mutex<RecycleAllocator>,
}


impl AccountManager {
    pub fn new() -> Self {
        Self {
            db: Mutex::new(BTreeMap::new()),
            account_id_allocator: Mutex::new(RecycleAllocator::new()),
        }
    } 
    pub async fn create_account(&self) -> usize {
        let account_id = self.account_id_allocator.lock().await.alloc();
        let new_account = Account::new(account_id);
        self.db.lock().await.insert(account_id, Arc::new(new_account));
        account_id
    }
    pub async fn get_account(&self, account_id: usize) -> Option<Arc<Account>> {
        self.db.lock().await.get(&account_id).cloned()
    }
}


lazy_static! {
    pub static ref ACCOUNT_MANAGER: AccountManager = AccountManager::new();
}


pub struct Account {
    account_id: usize,
    pub inner: Mutex<AccountInner>,
}

pub struct AccountInner {
    pub balance: usize,
}

impl Account {
    pub fn new(account_id: usize) -> Self {
        Self {
            account_id,
            inner: Mutex::new(AccountInner {
                balance: 0,
            }),
        }
    }
    pub fn account_id(&self) -> usize {
        self.account_id
    }
}