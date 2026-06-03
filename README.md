# indices-verification

Independently verify **The Road to Autonomy Indices**.

Every twelve hours, each published index value is sealed and its Merkle root is
time-stamped by independent RFC 3161 Time-Stamping Authorities. Using only the
public files for a sealed cycle, this tool recomputes the root from the
published values and confirms it matches the externally anchored timestamp. **No
trust in AUTNMY AI is required.**

It proves exactly two things, and only these two:

- **Integrity** — a published value was not altered after it was sealed.
- **Timing** — the value existed at the certified time, attested by an
  authority whose clock the publisher does not control.

It does **not** assess whether a value is correct, fair, or well computed. That
is governed by the [Benchmark Statement](https://indices.roadtoautonomy.com/benchmark-statement/)
and the methodology. The seal is narrow by design.

## Install

```bash
pip install "git+https://github.com/AUTNMY-AI/indices-verification.git"
```

Or install the hosted build without cloning:

```bash
pip install https://verification.roadtoautonomy.com/indices-verification.tar.gz
```

Either way this installs the `indices-verify` command.

## Use

Download a cycle's public files into a folder, then verify. Cycle ids and their
files are listed in the [audit log](https://indices.roadtoautonomy.com/verification/log/).

```bash
mkdir cycle && cd cycle
CYCLE=2026-06-03-1200   # pick a cycle id from the audit log
BASE=https://indices.roadtoautonomy.com/verification/$CYCLE
curl -O $BASE/cells.json
curl -O $BASE/tree.json
curl -O $BASE/root-digicert.tsr
curl -O $BASE/root-sectigo.tsr

# verify the whole cycle: recompute the root, match it to the anchored token
indices-verify verify-cycle .

# verify a single operator value via its Merkle proof
indices-verify verify-operator . --index robotaxi --operator waymo
```

A tampered value produces a different root that matches neither `tree.json` nor
the timestamp tokens, and the tool reports `NOT VERIFIED`.

To additionally verify each token's signature and certificate chain (not just
the message imprint), pass the Time-Stamping Authority root certificate(s):

```bash
indices-verify verify-cycle . --trust-root digicert-root.pem --trust-root sectigo-root.pem
```

## What gets published per cycle

| File | Contents |
| --- | --- |
| `cells.json` | The published composite and pillar values for every operator. |
| `tree.json` | The Merkle root plus an inclusion proof for each value. |
| `root-*.tsr` | The RFC 3161 timestamp tokens from each Time-Stamping Authority. |

## How it works

1. Each value is serialized in a frozen canonical form (RFC 8785 JCS, scores as
   fixed-precision strings) and hashed into an RFC 6962 Merkle tree.
2. The tool recomputes the single 32-byte root **from `cells.json` directly**,
   never trusting `tree.json`.
3. The recomputed root is checked against the message imprint inside each
   `root-*.tsr` token; with `--trust-root`, the token signature and certificate
   chain are verified too.
4. A single operator is verified by walking its Merkle path up to the anchored
   root.

The canonicalization and tree rules are the same code the publisher uses,
vendored here so the two can never silently drift. The canonicalization is
versioned (`jcs-1`); if it ever changes, old cycles keep verifying under the
old rule.

## Security

This is read-only verification code with no secrets and no network writes. Its
guarantees rest on the external RFC 3161 signatures, not on any secrecy of this
tool, which is the point of publishing it openly.

## License

[MIT](LICENSE).
