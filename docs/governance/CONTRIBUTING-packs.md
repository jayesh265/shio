# Contributing a pack

Anyone can write a pack and publish it to a registry. A pack that passes the validator can be installed by hash and
used by any Shio agent; whether it says anything true about a regulation is for its reviewers, which is why only a
`reviewed` pack may claim compliance.

## 1. Write it

Start from a built-in pack with a similar shape (`shio/packs/med.trial` for checks with fixtures,
`shio/packs/gov.nist-ai-rmf` for a framework mapping). The format is in [D2-pack-format.md](D2-pack-format.md).

- Choose an id in your own namespace: `acme.discharge`, not `med.discharge`.
- Every runtime check is deterministic, returns a `Verdict`, and never repeats sensitive values in its reason.
- Every runtime check has pass, fail **and adversarial** fixtures. Adversarial means an attack or a trap: hidden
  instructions in a document, a value that looks right but isn't, a missing fact that must not pass.
- Write requirements in your own words. Don't paste a standard's text unless its licence allows it.
- The README says what the pack does not cover, under a "Limits" heading.
- Status starts at `draft`. Don't write "compliant", "certified" or "conforms to" until it is `reviewed`, with the
  reviewers named in `review`.

## 2. Validate it

```bash
shio pack validate path/to/acme.discharge          # structure, fixtures run, no unreviewed compliance claims
shio pack redteam path/to/acme.discharge -o rt.json && shio eval rt.json   # its attacks, as a CI suite
```

## 3. Publish it

```bash
shio pack publish path/to/acme.discharge --index registry/index.json --store registry/store --publisher "Acme"
```

Publishing validates again, refuses a version that was already published with different content (bump the version),
writes a deterministic archive, and records its sha256 and the pack's tree sha256 in a signed index entry (signed with
`SHIO_SIGNING_KEY`). Serve `index.json` and `store/` as static files over HTTPS to share them.

## 4. Install it

```bash
shio pack install "acme.discharge@^1.0" --index https://packs.example/index.json --to packs/ --pubkey registry.pub
```

The highest matching version is fetched, its hash and the entry's signature checked, it is extracted safely (no
absolute paths, `..`, or links) and validated again. Pin it in your agent manifest by sha256.

## Review

To move a pack to `reviewed`, the reviewers (counsel; for clinical packs, a clinical safety lead) add their names and
dates to `review`, and publish a new version. A record always cites the version in force when it was decided, so
reviewing a new version never rewrites the history of decisions made under an older one.
