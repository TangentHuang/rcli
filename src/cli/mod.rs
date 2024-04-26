mod base64;
mod csv;
mod genpass;
mod http;
mod text;

pub use self::{base64::*, csv::*, genpass::*, http::*, text::*};
use clap::Parser;
use enum_dispatch::enum_dispatch;
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(name="rcli",version,author,about,long_about = None)]
pub struct Opts {
    #[command(subcommand)]
    pub cmd: SubCommand,
}

#[derive(Parser, Debug)]
#[enum_dispatch(CmdExecutor)]
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
