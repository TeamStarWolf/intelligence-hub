# Private intelligence archive

## Status and boundary

This is a standalone, offline archive foundation in `intelligence_hub/archive.py`.
Its first source is an explicitly selected, retained public Intelligence Hub
snapshot. Source implementation and review do not establish a successful import,
recovery, scheduled ingestion or a complete decade archive. Record actual operator
results separately. No archive operation is added to the collector or workflow.

The archive has **no listener, public API, network call, provider, login or new
dependency**. It never opens local documents, devices or a URL found in a record.
The existing Pages package allowlist is unchanged: the database, inbox, exports
and receipts remain outside `site/` and inside ignored `.state/`.

## Fixed paths and explicit operation

The command accepts no source, database or destination path arguments:

| Purpose | Fixed repository-relative location |
| --- | --- |
| Operator-staged public snapshot | `.state/archive-foundation/inbox/feed.json` |
| SQLite archive | `.state/archive-foundation/archive.sqlite3` |
| Selected private exports and receipts | `.state/archive-foundation/exports/` |

After independent source/security review, an operator may copy a verified public
snapshot into the fixed inbox and record its exact SHA-256. Staging that copy is
separate from ingest. Do not copy Clifford's operating database or private state
into this public-source archive. The operator pin detects byte mismatch; it is
not a signature, publisher-authenticity check or declassification decision.

Run commands from this repository's root, replacing placeholders deliberately:

```text
python -m intelligence_hub.archive status
python -m intelligence_hub.archive ingest --sha256 <64-lowercase-hex>
python -m intelligence_hub.archive search --snapshot <snapshot-sha256> --kind article --query <text> --limit 20
python -m intelligence_hub.archive search --snapshot <snapshot-sha256> --kind cve --query <CVE-ID> --limit 20
python -m intelligence_hub.archive history --kind cve --id <CVE-ID> --limit 20
python -m intelligence_hub.archive export --snapshot <snapshot-sha256>
```

There is no automatic ingest, retry, pruning, deletion, restore or publication.
`status` does not initialize a missing database. Search/history/export open an
existing database in SQLite read-only mode; they cannot fetch missing inputs.
An explicit ingest is the only database writer. SQLite locking and filesystem
metadata activity remain possible even for read-only connections.

## Snapshot and version model

Only the bounded, current public **schema 3** snapshot is admitted. Unknown
top-level/source/article/CVE fields are rejected; header types, dates, source
observations, partial-intake accounting, article provenance, structured guidance
and the exact article-mentioned CVE union are checked. Existing pure collector
and CVE validators are reused, without calling their fetch/build functions.
Successful validation does not corroborate a publisher claim or sanitize every
supplied string.

One transaction records a snapshot's received-byte digest, canonical structured
digest, input size, generated/import dates, supplied revisions and complete
header. Separate rows preserve source observations, articles and CVE briefs by
entity identity and canonical-content digest. Ordered membership associates the
exact versions with each snapshot. Article-to-CVE associations support search.

An identical input SHA is a logical no-op: it adds no snapshot, membership or
version rows. A changed entity creates a new version rather than replacing old
history. Identical versions are shared across snapshots. Source observations
keep their attempt/accepted dates, status, hash and intake report; CNA fact dates
and latest-attempt dates remain separate. These are observations of received
snapshots, not a live source, installed-product or exploitation assessment.

The archive preserves all saved fields, array order and source/article/CVE
membership order. It does not retain every original raw snapshot as another
large blob. Whitespace, JSON escape spelling and object-key order are not reconstructed;
the original input digest remains distinct from the canonical structured digest.
Keep the original evidence separately if exact received bytes are required.

## Queries and exports

Search requires an exact snapshot SHA and one kind: `article`, `cve` or `source`.
It searches identity/title/URL and, for articles, CVE mentions. SQL uses bound
parameters and escaped literal `LIKE` input; no SQL expression, file path or
regular expression is accepted. This is bounded substring search, not a full
Unicode search engine or relevance ranking. The response names the selected
historical snapshot and returns IDs, version hashes, titles and URLs, not full
guidance bodies. History reports bounded observed-version membership across
imports; import clocks are not publication/event clocks.

An explicit export reconstructs one selected snapshot, verifies record digests,
contiguous membership order and the complete canonical structured digest, and
validates the result again. It writes `<snapshot-sha256>.private.json` and a
separate `.receipt.private.json` exclusively in the fixed export directory.
Existing output is never overwritten. The receipt distinguishes input versus
export hashes and marks sharing/publication **unapproved**.

Export remains private even though inputs were public: records can contain
arbitrary supplied text. It is not a new public Pages input or permission to
publish. Partial output can remain after interruption or disk failure. A file's
existence alone is not completion; require successful command output and the
matching receipt/hash before use. Reconcile uncertain writes before retrying.

## Resource and storage guards

- Input and selected export: at most **16 MiB** each; strict UTF-8/JSON, duplicate
  member and nonfinite-number rejection, bounded tree depth/node/string counts.
- Snapshot: at most 8,000 articles, 15,000 CVE briefs and 97 source observations;
  a version payload or saved header is at most 256 KiB.
- Archive: at most 10,000 snapshots and **1 GiB of SQLite pages** with 4 KiB pages;
  the existing main-file size is also checked. There is no automatic retention
  policy or silent removal when a guard is reached.
- Before ingest, free disk must cover at least 64 MiB or the current database
  size plus four times the input size, whichever is larger. Export has a separate
  free-space check. These are conservative preflight checks, not reservations.
- SQLite uses a delete journal, full synchronization, foreign keys, fixed schema
  checks, disabled extension loading and `trusted_schema=OFF`. Transactions use
  a five-second lock timeout and progress callbacks with best-effort 30-second
  write/10-second read budgets. OS calls, locking and individual SQLite work are
  not a guaranteed hard wall-clock or memory limit.
- Search/history return at most 100 entries; command JSON output is capped at
  128 KiB. Oversized output fails rather than silently dropping guidance.

The 1 GiB database guard does **not** include rollback journals, SQLite sidecars,
inbox copies, exports, retained receipts or backups. Check actual free space and
growth before further imports. Existing active/unresolved sidecars are refused
for review, never deleted or silently mixed with another database copy.

## Privacy, concurrency and recovery limits

Fixed directories/files reject ordinary symlink/reparse/offline paths and file
hardlinks. Bounded source reads compare path/handle identity and recheck the
inbox digest before commit. SQLite serializes writers and rolls back ordinary
transaction failures. These checks detect ordinary drift; they do not make a
host compromised under the same user an adversarial filesystem sandbox.

POSIX creation modes request private access. Windows inherits the host's ACLs;
no encryption or independently verified ACL policy is installed here. Protect
the host, repository write access and private state. A malformed or unrecognized
archive is refused; no schema migration or repair is attempted. A failed first
import may leave an empty/unrecognized database file for review.

This foundation has no archive backup command or proven restore. A safe future
recovery procedure must preserve current files, stop archive writers, create a
consistent SQLite backup or a coherent stopped copy, and inspect a separate
restore copy before replacing anything. Do not copy only a live main database
while discarding required journal/WAL state. Same-disk copies are not disaster
protection. Transactional imports, synchronization and hashes do not establish
power-loss recovery, filesystem durability, complete source history or security.
