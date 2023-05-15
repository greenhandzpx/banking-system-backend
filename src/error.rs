pub type BankResult<T> = Result<T, Error>;

pub enum Error {
    BalanceNotEnough,
}
