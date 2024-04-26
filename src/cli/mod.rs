mod base64;
mod csv;
mod genpass;
mod http;
mod text;

pub use self::base64::{Base64Format, Base64subCommand};
pub use self::csv::{CsvOpts, OutputFormat};
use self::genpass::GenPassOpts;
pub use self::http::HttpSubCommand;
pub use self::text::{TextSignFormat, TextSubCommand};
use crate::CmdExecutor;
use clap::Parser;
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(name="rcli",version,author,about,long_about = None)]
pub struct Opts {
    #[command(subcommand)]
    pub cmd: SubCommand,
}

#[derive(Parser, Debug)]
pub enum SubCommand {
    #[command(name = "csv", about = "Show CSV, or convert CSV to other formats")]
    Csv(CsvOpts),

    #[command(name = "genpass", about = "Generate a random password")]
    GenPass(GenPassOpts),

    #[command(subcommand, about = "Base64 encode or decode")]
    Base64(Base64subCommand),

    #[command(subcommand, about = "Text sign/verify, or generate key")]
    Text(TextSubCommand),

    #[command(subcommand, about = "HTTP static file server")]
    Http(HttpSubCommand),
}

impl CmdExecutor for SubCommand {
    async fn execute(self) -> anyhow::Result<()> {
        match self {
            SubCommand::Csv(opts) => opts.execute().await,
            SubCommand::GenPass(opts) => opts.execute().await,
            SubCommand::Base64(sub_cmd) => sub_cmd.execute().await,
            SubCommand::Text(sub_cmd) => sub_cmd.execute().await,
            SubCommand::Http(sub_cmd) => sub_cmd.execute().await,
        }
    }
}

fn verify_path(path: &str) -> Result<PathBuf, &'static str> {
    let p = Path::new(path);
    if p.exists() && p.is_dir() {
        Ok(path.into())
    } else {
        Err("Path does not exist or is not a directory")
    }
}

fn verify_file(filename: &str) -> Result<String, &'static str> {
    if filename == "-" || Path::new(filename).exists() {
        Ok(filename.into())
    } else {
        Err("Input file does not exist")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_input_file() {
        assert_eq!(verify_file("-"), Ok("-".into()));
        assert_eq!(verify_file("*"), Err("Input file does not exist"));
        assert_eq!(verify_file("Cargo.toml"), Ok("Cargo.toml".into()));
        assert_eq!(
            verify_file("not_exist.txt"),
            Err("Input file does not exist")
        );
    }
}
