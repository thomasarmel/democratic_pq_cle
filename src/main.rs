use std::str::FromStr;
use democratic_pq_cle::certificateless_qc_mdpc::CertificatelessQcMdpc;
use democratic_pq_cle::math::{binom, nth_combination};
use democratic_pq_cle::my_bool::MyBool;
use democratic_pq_cle::utils::generate_random_weight_vector_to_invertible_matrix;
use num::integer::Roots;
use num::Integer;
use num_bigint::{BigUint, ToBigInt};
use verifiable_secret_sharing::ShamirSecretSharing as SSS;
use democratic_pq_cle::{P, T, VOTES_THRESHOLD, W};

const MESSAGE: &'static str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX";
// Warning: Must regenerate prime when increasing P: size = P << 2 ??
const SHAMIR_PRIME: &'static str = "160709158425158035654685227325973365624663273287406113461145953791824931969868553857443975598081782425782238924631575521690050079686432679571207930665013242855292363190357607432848330361342045009708758970141017149750410159672120775535180892519552660606472653252094488915011087690901235041024920903936951266492676478477152395959987044121055694487824454548513291118740413831170656966083481545846322276907730288640437837123252820411487356601254412916684662133890553145125006204300890659";

fn main() {
    /*let prime = Generator::new_prime(P << 2);
    println!("{}", prime);*/
    let shamir_prime = BigUint::from_str(SHAMIR_PRIME).unwrap();
    let shamir_prime = shamir_prime.to_bigint().unwrap();

    //let si_weight = max((W >> 1).nth_root(3), 10); // ???
    let si_weight = (W >> 1).nth_root(2); //7;//(W >> 1).nth_root(3); // TODO il faudrait au moins 7 pour securité, 13 pour P = 4000
    let binomial_coef_s_i_generation = binom(P, si_weight).to_bigint().unwrap();

    let mut nodes_currently_in_system_count = 0;

    // Init node 1, using a random s_i vector

    let s_i_node_1 = generate_random_weight_vector_to_invertible_matrix(P, si_weight);
    //println!("s_i: {:?}", s_i_node_1);
    let node_1 = CertificatelessQcMdpc::init(1, P, W, T, &s_i_node_1);

    nodes_currently_in_system_count += 1;
    let (node_1_public_key, node_1_witness) = node_1.public_key_and_witness();
    println!(
        "Node 1: Public key verified: {}",
        node_1_public_key.check_is_valid(1, &s_i_node_1, &node_1_witness, W)
    );

    let node_1_private_key = node_1.private_key();
    //println!("{}", node_1_private_key.first_line().iter().map(|x| if **x { '1' } else { '0' }).collect::<String>());
    //println!("{}", node_1_private_key.weight());
    let encrypted = node_1_public_key.encrypt(MESSAGE.as_bytes());
    println!(
        "Encrypted: {}",
        encrypted
            .iter()
            .map(|x| if **x { '1' } else { '0' })
            .collect::<String>()
    );
    //std::fs::write("H.txt", node_1_private_key.to_string()).expect("Unable to write file");
    //std::fs::write("enc.txt", encrypted.iter().map(|x| if **x { '1' } else { '0' }).collect::<String>()).expect("Unable to write file");
    //println!("{} {}", encrypted.nrows(), encrypted.ncols());
    let encrypted_bis = node_1_public_key.encrypt(MESSAGE.as_bytes()); // as decryption is probabilist, it increases the chance to decrypt the message
                                                                       //std::fs::write("enc2.txt", encrypted_bis.iter().map(|x| if **x { '1' } else { '0' }).collect::<String>()).expect("Unable to write file");
                                                                       //println!("Encrypted: {}", encrypted);
                                                                       //return;

    let decrypted = node_1_private_key
        .decrypt(&encrypted)
        .or(node_1_private_key.decrypt(&encrypted_bis))
        .unwrap();
    //println!("Decrypted: {:?}", decrypted);
    println!(
        "Node 1: Decrypted data: {}",
        std::str::from_utf8(&decrypted[0..MESSAGE.len()]).unwrap()
    );

    // Node 1 accepts the new node 2

    // The signature should be broadcast to all nodes, in order to allow all nodes to verify the new node initialization vector
    let new_node_2_signature_from_node_1 = node_1.accept_new_node(2);
    println!(
        "New node 2 signature valid from node 1: {}",
        new_node_2_signature_from_node_1.is_valid(&node_1_witness, 2)
    );
    //return;

    let shamir_voting_threshold =
        ((nodes_currently_in_system_count as f32) * VOTES_THRESHOLD).ceil() as usize;
    println!(
        "Accepting a new node... Voting threshold = {}",
        shamir_voting_threshold
    );
    let sss = SSS {
        threshold: shamir_voting_threshold,
        share_amount: 1,
        prime: shamir_prime.clone(),
    };
    //println!("{}", new_node_2_signature.to_shamir_share(1).1);
    //println!("{}", sss.recover(&[new_node_2_signature.to_shamir_share(1)]));
    let s_node_2_combination_index = sss
        .recover(&[new_node_2_signature_from_node_1.to_shamir_share()])
        .mod_floor(&binomial_coef_s_i_generation);
    //println!("{}", s_node_2_combination_index);
    let mut s_i_node_2 = vec![MyBool::from(false); P];
    for index_to_flip in nth_combination(
        P,
        si_weight,
        s_node_2_combination_index.to_biguint().unwrap(),
    ) {
        s_i_node_2[index_to_flip] = MyBool::from(true);
    }
    //println!("s_i_node_2: {:?}", s_i_node_2);
    let node_2 = CertificatelessQcMdpc::init(2, P, W, T, &s_i_node_2);
    nodes_currently_in_system_count += 1;
    let (node_2_public_key, node_2_witness) = node_2.public_key_and_witness();
    println!(
        "Node 2: Public key verified: {}",
        node_2_public_key.check_is_valid(2, &s_i_node_2, &node_2_witness, W)
    );

    let node_2_private_key = node_2.private_key();
    //println!("Public key: {:?}", public_key);
    let encrypted = node_2_public_key.encrypt(MESSAGE.as_bytes());
    let encrypted_bis = node_2_public_key.encrypt(MESSAGE.as_bytes()); // as decryption is probabilist, it increases the chance to decrypt the message
                                                                       //println!("Encrypted: {}", encrypted);

    let decrypted = node_2_private_key
        .decrypt(&encrypted)
        .or(node_2_private_key.decrypt(&encrypted_bis))
        .unwrap();
    //println!("Decrypted: {:?}", decrypted);
    println!(
        "Node 2: Decrypted data: {}",
        std::str::from_utf8(&decrypted[0..MESSAGE.len()]).unwrap()
    );

    // Node 1 and 2 accepts the new node 3
    let new_node_3_signature_from_node_1 = node_1.accept_new_node(3);
    let new_node_3_signature_from_node_2 = node_2.accept_new_node(3);
    println!(
        "New node 3 signature valid from node 1: {}",
        new_node_3_signature_from_node_1.is_valid(&node_1_witness, 3)
    );
    println!(
        "New node 3 signature valid from node 2: {}",
        new_node_3_signature_from_node_2.is_valid(&node_2_witness, 3)
    );

    let shamir_voting_threshold =
        ((nodes_currently_in_system_count as f32) * VOTES_THRESHOLD).ceil() as usize;
    println!(
        "Accepting a new node... Voting threshold = {}",
        shamir_voting_threshold
    );
    let sss = SSS {
        threshold: shamir_voting_threshold,
        share_amount: 1,
        prime: shamir_prime.clone(),
    };
    let s_node_3_combination_index = sss
        .recover(&[
            new_node_3_signature_from_node_1.to_shamir_share(),
            new_node_3_signature_from_node_2.to_shamir_share(),
        ])
        .mod_floor(&binomial_coef_s_i_generation);
    let mut s_i_node_3 = vec![MyBool::from(false); P];
    for index_to_flip in nth_combination(
        P,
        si_weight,
        s_node_3_combination_index.to_biguint().unwrap(),
    ) {
        s_i_node_3[index_to_flip] = MyBool::from(true);
    }
    let node_3 = CertificatelessQcMdpc::init(3, P, W, T, &s_i_node_3);
    nodes_currently_in_system_count += 1;
    let (node_3_public_key, node_3_witness) = node_3.public_key_and_witness();
    println!(
        "Node 3: Public key verified: {}",
        node_3_public_key.check_is_valid(3, &s_i_node_3, &node_3_witness, W)
    );
    let node_3_private_key = node_3.private_key();
    let encrypted = node_3_public_key.encrypt(MESSAGE.as_bytes());
    let encrypted_bis = node_3_public_key.encrypt(MESSAGE.as_bytes()); // as decryption is probabilist, it increases the chance to decrypt the message
    let decrypted = node_3_private_key
        .decrypt(&encrypted)
        .or(node_3_private_key.decrypt(&encrypted_bis))
        .unwrap();
    //println!("Decrypted: {:?}", decrypted);
    println!(
        "Node 3: Decrypted data: {}",
        std::str::from_utf8(&decrypted[0..MESSAGE.len()]).unwrap()
    );

    println!(
        "Nodes currently in system: {}",
        nodes_currently_in_system_count
    );
}
