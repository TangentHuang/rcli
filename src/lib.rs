mod cli;
mod process;

pub use cli::Opts;
pub use cli::SubCommand;
pub use cli::{Base64Format, Base64subCommand};
pub use process::process_b64_decode;
pub use process::process_b64_encode;
pub use process::process_csv;
pub use process::process_gen_pass;
