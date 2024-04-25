// rcli csv -i input.csv -o output.json

use clap::Parser;
use rcli::{
    process_b64_decode, process_b64_encode, process_csv, process_gen_key, process_gen_pass,
    process_sign, process_verify, Base64subCommand, Opts, SubCommand, TextSignFormat,
    TextSubCommand,
};
use std::fs;
use zxcvbn::zxcvbn;

fn main() -> anyhow::Result<()> {
    let opts = Opts::parse();
    match opts.cmd {
        SubCommand::Csv(opt) => {
            let output = if let Some(output) = opt.output {
                output.clone()
            } else {
                format!("output.{}", opt.format)
            };
            process_csv(&opt.input, &output, opt.format)?
        }
        SubCommand::GenPass(opt) => {
            let password = process_gen_pass(
                opt.length,
                !opt.no_uppercase,
                !opt.no_lowercase,
                !opt.no_number,
                !opt.no_symbol,
            )?;
            println!("{}", password);
            let estimate = zxcvbn(&password, &[])?;
            eprint!("Password strength: {}", estimate.score());
        }
        SubCommand::Base64(subcmd) => match subcmd {
            Base64subCommand::Encode(opt) => {
                let encode = process_b64_encode(&opt.input, opt.format)?;
                println!("{}", encode);
            }
            Base64subCommand::Decode(opt) => {
                let decode = process_b64_decode(&opt.input, opt.format)?;
                println!("{}", decode);
            }
        },
        SubCommand::Text(subcmd) => match subcmd {
            TextSubCommand::Sign(opt) => {
                let sig = process_sign(&opt.input, &opt.key, opt.format)?;
                println!("{}", sig);
            }
            TextSubCommand::Verify(opt) => {
                let verify = process_verify(&opt.input, &opt.key, &opt.sig, opt.format)?;
                println!("{}", verify);
            }
            TextSubCommand::GenKey(opt) => {
                let key = process_gen_key(opt.format)?;
                match opt.format {
                    TextSignFormat::Blake3 => {
                        let name = opt.output.join("blake3.txt");
                        fs::write(name, &key[0])?;
                    }
                    TextSignFormat::Ed25519 => {
                        let name = &opt.output;
                        fs::write(name.join("ed25519.sk"), &key[0])?;
                        fs::write(name.join("ed25519.pk"), &key[1])?;
                    }
                }
            }
        },
    }
    Ok(())
}
