mod cli;
mod process;
mod utils;

pub use cli::Opts;
pub use cli::SubCommand;
pub use cli::TextSubCommand;
pub use cli::{Base64Format, Base64subCommand, HttpSubCommand, TextSignFormat};
pub use process::{
    process_b64_decode, process_b64_encode, process_csv, process_gen_key, process_gen_pass,
    process_http_serve, process_sign, process_verify,
};

#[allow(async_fn_in_trait)]
pub trait CmdExecutor {
    async fn execute(self) -> anyhow::Result<()>;
}
