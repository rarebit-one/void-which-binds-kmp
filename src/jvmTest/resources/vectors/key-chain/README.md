# Key-chain vectors

A space-key history (heyarr ADR-0103): when a space's key is rotated from epoch
N-1 to N, the client seals key N-1 under key N with `encryption.SealSpaceKey`
and stores the result as history row N. A holder of the current key opens each
row in turn (`encryption.OpenSpaceKey`) to recover every earlier key.

Format of a sealed key, exactly 72 bytes:

    nonce (24) ‖ XChaCha20-Poly1305(key = sealing key, nonce,
                                    plaintext = the 32-byte sealed key,
                                    associated data = "void-which-binds/space-key-chain/v1")

The associated data separates this from an encrypted change
(`EncryptChange`, which has none): a sealed key never opens as a change and
a change never opens as a sealed key.

`three-epochs.json` is deterministic (fixed keys and nonces), so
`go test ./encryption -run TestKeyChainVector` regenerates it and requires the
committed file to match byte for byte; `-update` rewrites it. An implementation
must open every `links[n]` with `keys[n]` to get `keys[n-1]`, and must refuse
every `refuse` blob with `keys[sealing_key_index]`. All keys are test-only.
