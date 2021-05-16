use clap::{App, Arg};
use dgc_lib::dgc;
use serde_json::Value;
use std::io::{self, Read, Write};

fn main() {
    let matches = App::new("dgc")
        .version("1.0")
        .author("Mauro Mandracchia <mauromandracchia@gmail.com>")
        .about("Encode and Decode for Digital Green Certificate")
        .subcommand(
            App::new("sign")
                .about("encode the message")
                .arg(
                    Arg::new("private_key")
                        .short('p')
                        .long("privateKey")
                        .value_name("PRIVATEKEY_FILE")
                        .about("Sets certificate from file")
                        .takes_value(true)
                        .unset_setting(clap::ArgSettings::UseValueDelimiter)
                        .required(true),
                )
                .arg(
                    Arg::new("certificate")
                        .short('c')
                        .long("certificate")
                        .value_name("CERTIFICATE_FILE")
                        .about("Sets certificate from file")
                        .takes_value(true)
                        .unset_setting(clap::ArgSettings::UseValueDelimiter)
                        .required(true),
                ),
        )
        .subcommand(
            App::new("verify").about("decode the message").arg(
                Arg::new("certificate")
                    .short('c')
                    .long("certificate")
                    .value_name("CERTIFICATE_FILE")
                    .about("Sets certificate from file")
                    .takes_value(true)
                    .unset_setting(clap::ArgSettings::UseValueDelimiter)
                    .required(true),
            ),
        )
        .get_matches();

    let mut message = Vec::new();
    let stdin = io::stdin();
    let mut handle = stdin.lock();
    handle.read_to_end(&mut message).unwrap();

    if let Some(ref matches) = matches.subcommand_matches("sign") {
        if matches.is_present("certificate")
            && matches.is_present("private_key")
            && message.len() > 0
        {
            let certificate = matches.value_of("certificate").unwrap();
            let private_key = matches.value_of("private_key").unwrap();
            let encoded_message = sign_with_file_certificate(
                certificate,
                private_key,
                &String::from_utf8(message).unwrap(),
            );
            let mut out = std::io::stdout();
            out.write_all(&("HC1:".to_owned() + &encoded_message.to_owned()).as_bytes())
                .unwrap();
            out.flush().unwrap();
        } else {
            println!("Required parameters");
        }
        return;
    }

    if let Some(ref matches) = matches.subcommand_matches("verify") {
        if matches.is_present("certificate") {
            // "$ myapp test -l" was run
            let certificate = matches.value_of("certificate").unwrap();
            let decode_message =
                verify_with_file_certificate(certificate, &message.to_owned()[4..]);

            println!("{}", decode_message);
        } else {
            println!("Required parameters");
        }
    }
}

fn sign_with_file_certificate(certificate: &str, private_key: &str, message: &str) -> String {
    let public = std::fs::read_to_string(certificate)
        .unwrap()
        .as_bytes()
        .to_vec();

    let private = std::fs::read_to_string(private_key)
        .unwrap()
        .as_bytes()
        .to_vec();

    dgc::sign(public, private, message)
}

fn verify_with_file_certificate(certificate: &str, message: &[u8]) -> Value {
    dgc::read(
        &std::fs::read_to_string(certificate)
            .unwrap()
            .as_bytes()
            .to_vec(),
        message,
    )
}
