# Op-log history cap golden vectors

Cross-implementation vectors for the **history cap** on the two signed op logs
(ADR-0007 for a person's membership log, ADR-0014 for an org's roster log, both
amended 2026-10-03, #122). void-which-binds-go generates them
(`go test ./enrolment ./roster -run TestCapVectors -update`), and
void-which-binds-kmp replays them verbatim.

## The rule

The protocol cap is **10,000 ops per log** (`enrolment.MaxLogOps`,
`roster.MaxLogOps`). Over a set of tokens:

1. Count the **well-formed** ops: those that pass the op-local half of rule 1
   (parse, typ, signature, canonical keys, the right `usr`/`org`, and for a
   roster op every signature's person context). A token that fails these is
   rejected as ever and never counts.
2. At most `max_ops` well-formed ops: evaluate the set whole, exactly as
   without a cap.
3. More: take the **anchored history**, the anchored ops plus every op they
   cite, transitively, within the set.
   - Membership: the anchored keys are genesis and, by fixpoint, the `dev` of
     every well-formed `add` signed by an anchored key (ignoring `prev`, time,
     removal and cosigs). An op is anchored when its `by` is.
   - Roster: the anchored authority keys are the org id and, by fixpoint, the
     `succ` of every anchored authority-shape re-root. An op is anchored when
     it is in the authority shape with an anchored `by`, or when any of its
     signatures (the primary, or a cosig that verifies) is plausible: its
     `usr` is named by an anchored `set`, and it is by that person's genesis
     key with no `bprev`, by a device that is a member of the person's log as
     of `bprev` (MemberAt), or, for a managed person, by a key an anchored
     `enrol` enrols. An anchored `set` names its `mem`; an anchored `enrol`
     enrols its `key`.
4. If the anchored history has more than `max_ops` ops, refuse the whole set:
   `log_too_large` (Go's `ErrLogTooLarge`). Otherwise evaluate the anchored
   history alone and reject every other well-formed op as **`unanchored`**.

Both branches are functions of the set. Nothing outside the anchored history
can be authorised, count toward a high-water or move the authority chain, so
the anchored ops' verdicts are what the whole set gives them; a stranger's
junk is only ever rejected and cannot push an honest log over the cap. An
anchored signer (a removed or stolen device of the person, a person named on
the roster) can.

## Layout

Each file follows its log's schema (`../membership/README.md` or
`../roster/README.md`), plus:

```jsonc
{
  "log":     "membership",      // or "roster": which schema and evaluator
  "max_ops": 6,                 // evaluate under this cap in place of 10,000
  "expect":  { … },             // the log's usual expect, when it evaluates
  "error":   "log_too_large"    // instead of expect, when the set is refused
}
```

`max_ops` exists so each case stays a handful of ops: a consumer passes it to
its evaluator through a test-only seam, exactly as Go's tests call
`evaluate(…, maxOps)`. The protocol constant is pinned separately (Go's
`TestMaxLogOpsIsTenThousand`), and `TestCapAtTheRealLimit` exercises the rule at
10,000 itself with sets generated in the test (10,000 ops evaluate, 10,001 are
refused, and 10,000 strangers' ops beside a two-op log are all `unanchored`).
Every permutation of `ops` (and of each person's ops) must give the same
answer.

## Cases

| case | what it pins |
|------|--------------|
| `membership-at-cap` | exactly 6 well-formed ops evaluate whole; malformed and bad-signature tokens do not count |
| `membership-over-cap` | 7 anchored ops: `log_too_large` |
| `membership-junk-unanchored` | 7 well-formed ops, 4 in the anchored history: a stranger's 3 uncited ops are `unanchored`, the one an honest op cites stays (unauthorised) |
| `membership-removed-device-counts` | the trade-off: a device genesis removed is still anchored, so its ops push the log to 7 and `log_too_large` |
| `roster-at-cap` | exactly 5 well-formed roster ops (the founding op included) evaluate whole; a bad-signature token does not count |
| `roster-over-cap` | 6 anchored roster ops: `log_too_large` |
| `roster-junk-unanchored` | 9 well-formed ops, 4 in the anchored history: a stranger key in the authority shape, a stranger as its own person (including its self-remove: a self-remove by someone no anchored `set` names is the one kind of verdict the cap changes) and a stranger's device signing as a person are `unanchored` |
| `roster-named-person-counts` | the trade-off: a viewer's self-signed ops are anchored, push the roster to 6 and `log_too_large` |
