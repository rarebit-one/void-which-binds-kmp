# Recovery-wrap vectors

End-to-end vault recovery from a recovery secret alone (docs/RECOVERY-SPEC.md §5):
a space key sealed for the recovery encryption key of the `counting-entropy`
recovery vector, a change encrypted under that key, and a heyarr recovery blob
(heyarr ADR-0022 addendum) carrying the sealed key.

The space key is sealed under the gen2 wrap label
`void-which-binds/space-key-wrap/v1` (ADR-0022). Sealing and encryption are
randomised, so the file is minted with
`go test ./encryption -run TestRecoveryWrapVector -update` only when a label it
depends on changes (last: the gen2 re-mint), and is otherwise only ever
**replayed**. The replay must unwrap the space key, decrypt the
change, and open the blob. `docs/recovery/reference.py selftest` checks the same
file from Python. All keys are test-only.
