use rand::prelude::SliceRandom;
use rand::Rng;
use zxcvbn::zxcvbn;

const UPPER: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
const LOWER: &[u8] = b"abcdefghjkmnpqrstuvwxyz";
const NUMBER: &[u8] = b"123456789";
const SYMBOL: &[u8] = b"!@#$%^&*_";

pub fn process_gen_pass(
    length: u8,
    upper: bool,
    lower: bool,
    number: bool,
    symbol: bool,
) -> anyhow::Result<()> {
    let mut rng = rand::thread_rng();
    let mut password = Vec::new();
    let mut chars = Vec::new();
    if upper {
        chars.extend_from_slice(UPPER);
        password.push(*UPPER.choose(&mut rng).unwrap());
    }
    if lower {
        chars.extend_from_slice(LOWER);
        password.push(*LOWER.choose(&mut rng).unwrap());
    }
    if number {
        chars.extend_from_slice(NUMBER);
        password.push(*NUMBER.choose(&mut rng).unwrap());
    }
    if symbol {
        chars.extend_from_slice(SYMBOL);
        password.push(*SYMBOL.choose(&mut rng).unwrap());
    }
    for _ in 0..length - password.len() as u8 {
        password.push(chars[rng.gen_range(0..chars.len())]);
    }
    password.shuffle(&mut rng);
    let password = String::from_utf8(password)?;
    println!("{}", password);

    let estimate = zxcvbn(&password, &[])?;
    eprint!("Password strength: {}", estimate.score());

    Ok(())
}
