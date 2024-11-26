use democratic_pq_cle::mc_eliece::{decrypt, encrypt};
use democratic_pq_cle::qc_mdpc::QcMdpc;

fn main() {
    let code = QcMdpc::init(2, 400, 30, 10);
    let message = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX".as_bytes();
    println!("Message length: {}", message.len());
    let public_key = code.get_public_key();
    let private_key = code.get_private_key();
    let encrypted = encrypt(&public_key, message).unwrap();
    println!("Encrypted: {}", encrypted);
    let decrypted = decrypt(&private_key, &encrypted).unwrap();
    println!("Decrypted: {:?}", decrypted);
    println!("{}", std::str::from_utf8(&decrypted[0..message.len()]).unwrap())
}
