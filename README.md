# Democratic QC-MDPC-based post-quantum certificateless encryption scheme

**:warning: This implementation is certainly not constant-time, meaning it could be vulnerable to side-channel attacks :warning:**

We propose a post-quantum certificateless encryption scheme based on a web of trust instead of a centralized Key Generation Center. Our scheme allows nodes to communicate securely. It is the nodes already present in the network that vote on the acceptance of new nodes, and agree on the shared key. The threshold required for the acceptance of a new node is configurable. Our protocol thus allows to completely operate without the Key Generation Center (or Key Distribution Center).

Our scheme is based on Quasi-Cyclic Moderate Density Parity Check Code McEliece, which is resistant to quantum computer attacks. The voting system uses Shamir secret sharing, coupled with the Kabatianskii-Krouk-Smeets signature scheme, both are also resistant to quantum computer attacks.

We provide a [formal verification](formal_verif/democratic_pq_cle.pv) of our protocol, in ProVerif. Scripts used for security analysis can be found in [security_assessments](/security_assessments) directory.

## Testing

Even if the implementation is supposed to be fast, you should run it in `Release` mode to get the best performance.

```bash
cargo run --release
```

## Changing the parameters

All the security parameters are defined in the `src/lib.rs` file.

## Formal verification

We modeled our protocol using ProVerif.

You can download it at https://bblanche.gitlabpages.inria.fr/proverif/.

Then launch the verification:

```bash
proverif formal_verif/democratic_pq_cle.pv
```