pub mod dgc {
    use std::io::Write;

    use aws_nitro_enclaves_cose::{sign::HeaderMap, COSESign1};
    use base45::{decode, encode_from_buffer};
    use flate2::{write::ZlibDecoder, write::ZlibEncoder};

    use openssl::{pkey::PKey, x509::X509};
    use serde_json::Value;

    pub fn sign(cert: Vec<u8>, private_key: Vec<u8>, data: &str) -> std::string::String {
        let key_id = &cert[..8];
        let private_key = PKey::private_key_from_pem(&private_key).unwrap();
        let v: Value = serde_json::from_str(&data).unwrap();
        let data = serde_cbor::to_vec(&v).unwrap();
        let mut header = HeaderMap::new();

        header.insert(
            serde_cbor::Value::Text("kid".to_string()),
            serde_cbor::Value::Bytes(key_id.to_vec()),
        );

        let signature = COSESign1::new(&data, &header, &private_key)
            .unwrap()
            .as_bytes(false)
            .unwrap();

        let mut encoder = ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&signature).unwrap();
        encode_from_buffer(encoder.finish().unwrap())
    }

    // Uncompresses a Zlib Encoded vector of bytes and returns a string or error
    // Here Vec<u8> implements Write
    fn decode_reader(bytes: Vec<u8>) -> Vec<u8> {
        let writer = Vec::new();
        let mut z = ZlibDecoder::new(writer);
        z.write_all(&bytes[..]).unwrap();
        z.finish().unwrap()
    }

    pub fn read(public_key: &Vec<u8>, data: &[u8]) -> Value {
        let public_key = X509::from_pem(public_key).unwrap().public_key().unwrap();
        let data = &String::from_utf8(data.to_vec()).unwrap();
        let data = decode(data);
        let data = decode_reader(data.to_vec());
        let data = COSESign1::from_bytes(&data)
            .unwrap()
            .get_payload(Some(&public_key))
            .unwrap();

        serde_cbor::from_slice(&data).unwrap()
    }
}
