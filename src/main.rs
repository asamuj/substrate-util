use base64::{engine::general_purpose, Engine};
use clap::Parser;
use substarte_util::{command::Commands, generate, parse};

fn main() {
    let commands = Commands::parse();
    match commands {
        Commands::Generate(args) => {
            generate::generate_encode_key(args.password, args.out_path).unwrap();
        }
        Commands::Parse(args) => {
            let ciphertext_bytes = general_purpose::STANDARD.decode(args.ciphertext).unwrap();

            let key = parse::decode_key(args.password, &ciphertext_bytes).unwrap();
            println!("pivate_key: {:?}", key)
        }
    }
}
