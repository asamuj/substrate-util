use clap::Parser;

#[derive(Parser, Debug)]
pub enum Commands {
    Generate(GenerateArgs),

    Parse(ParseArgs),
}

/// Arguments for the `generate` subcommand
#[derive(Parser, Debug)]
pub struct GenerateArgs {
    /// The password to use for generating the JSON file
    #[arg(short, long)]
    pub password: String,

    /// The output path for the generated JSON file
    #[arg(short, long)]
    pub out_path: String,
}

/// Arguments for the `parse` subcommand
#[derive(Parser, Debug)]
pub struct ParseArgs {
    /// The password to use for parsing the encrypted data
    #[arg(short, long)]
    pub password: String,

    /// The base64-encoded ciphertext to be parsed
    #[arg(short, long)]
    pub ciphertext: String,
}
