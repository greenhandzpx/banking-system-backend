use std::sync::Arc;

use crate::{
    db::Account,
    error::{BankResult, Error},
};

pub struct Transaction {
    src: Arc<Account>,
    dst: Arc<Account>,
    amount: usize,
}

impl Transaction {
    pub fn new(src: Arc<Account>, dst: Arc<Account>, amount: usize) -> Self {
        Self { src, dst, amount }
    }

    /// A simple locking rule:
    /// We always lock the smaller account first.
    pub async fn start(&self) -> BankResult<()> {
        let (mut src_locked, mut dst_locked) = {
            if self.src.account_id() == self.dst.account_id() {
                return Ok(());
            }
            if self.src.account_id() < self.dst.account_id() {
                let src_locked = self.src.inner.lock().await;
                let dst_locked = self.dst.inner.lock().await;
                (src_locked, dst_locked)
            } else {
                let dst_locked = self.dst.inner.lock().await;
                let src_locked = self.src.inner.lock().await;
                (src_locked, dst_locked)
            }
        };
        if src_locked.balance < self.amount {
            return Err(Error::BalanceNotEnough);
        }
        src_locked.balance -= self.amount;
        dst_locked.balance += self.amount;
        Ok(())
    }
}
