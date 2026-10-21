# Relay store migration

Relay nodes now admit only validated opaque propagation data to a durable store.
A packet proof follows complete validation and acknowledged durable admission.
Resource completion still means transport completion; it does not certify the
receiver's application storage. Ordinary message archives are separate from
relay storage and must never be copied into it.

## Startup and recovery

A new store can initialize automatically. An existing legacy directory requires
explicit offline migration. An incomplete migration, invalid committed record,
unsupported filesystem, or unavailable storage prevents hosting. Daemons fail
startup when required relay storage is unavailable. Applications retain the
user's hosting preference but show hosting as unavailable until recovery succeeds.
There is no automatic in-memory fallback for a durable host. Startup checks each
committed record's index, provenance, size and destination without rereading
whole message bodies; every read verifies the full body, and a body that fails
is not served.

Stop every process that can write the store, including service supervisors and
scheduled restarts. Then run the candidate daemon against the correct config:

```sh
lxmd-rs --config /path/to/config --migrate-propagation-store --relay-writers-stopped
```

Check `lxmd-rs --help` for the config-path option supported by your build. The
writer-stopped flag is an explicit assertion that supervisors have been stopped.
The tool also holds the store's OS lock and refuses when it finds another known
Ratspeak/LXMF daemon process, or cannot enumerate processes. Older binaries do not
honor the new lock; manually restarting one while migration runs is unsupported.
The process-name check cannot discover every renamed or custom relay program.

On iOS and Android, use the application's inbox recovery action for its private
store. The app first stops and joins its hosting and sync workers. Recovery
checks native application ownership and takes the same exclusive store lock;
it does not run the desktop process-list command or accept arbitrary external
directories. iOS recovery is restricted to the main app's private data container,
excluding extensions and shared app groups. Android recovery additionally
requires an exclusive app UID, the default app process, and no declared secondary
processes. Shared storage, shared UIDs and unverified ownership remain unavailable
for automatic recovery. Keep the original files and resolve the ownership or
storage error before retrying; do not remove the guard or copy archives into the
live store.

The migrator inventories relative paths, lengths and SHA-256 hashes before
moving anything. Symbolic links, special files, changed inventory and conflicting
unowned destinations stop migration without overwriting originals. It preserves
the legacy directory as `<store>.legacy-quarantine`, writes a regular-file guard
at the old path, and creates `<store>.v2`. The sibling `<store>.migration` journal
records every transition. Interrupted runs resume through the same command;
do not remove journals or guards to force startup. Windows directory publication
uses recorded sibling moves rather than inferring durability from existence.

The completion report gives the number and size of preserved files. Legacy
files are not offered, served, or counted as live relay messages. Their apparent
encryption shape, filename, previous app version, or old directory location does
not establish opaque-ingress provenance. Migration never automatically deletes
or expires the archive.

## Explicitly trusted recovery

Recovery requires independent, per-entry evidence of the original opaque
propagation ingress. A directory-wide assertion is insufficient. An operator
can supply a MessagePack named-map `TrustedRecoveryManifest` with these fields:

| Field | Value |
| --- | --- |
| `version` | `2` |
| `provenance` | Nonempty explanation of the independently checked evidence |
| `entries` | Array of the exact authorized records |
| Entry `archive_relative_path` | Relative path from the committed inventory |
| Entry `content_hash` | SHA-256 of the complete stored bytes, as 32 integer bytes |
| Entry `transient_id` | SHA-256 of destination+ciphertext, excluding a trailing PN stamp |
| Entry `stamped` | Whether the file includes the 32-byte PN stamp |
| Entry `stored_at` | Finite, nonnegative receipt timestamp |

Use the exported Rust structs and `rmp_serde::to_vec_named` to encode the record.
Review the manifest and independently record its SHA-256. Supply that approved
digest separately; merely hashing an unreviewed manifest does not establish trust.

```sh
lxmd-rs --config /path/to/config --migrate-propagation-store --relay-writers-stopped \
  --recover-propagation-manifest /path/to/recovery.msgpack \
  --recovery-manifest-sha256 APPROVED_SHA256_HEX
```

The importer checks the complete archive against its committed inventory, every
selected path/hash/TID, ciphertext framing, positive plaintext rejection, actual
stamp strength, and current size/quota policy before publication. Unstamped
recovery requires both explicit provenance and a zero minimum stamp policy.
Entries without evidence remain quarantined. Repeating the exact approved import
is idempotent; it cannot replace a different first accepted image. A failed IO
can leave a valid subset committed, so retain the manifest and retry.

## Library integration

Use `PropagationNode::with_storage` for a durable host. Keep readiness bound to
the active identity generation and drain the old generation's workers before
opening or migrating its store. `begin_offline_migration` returns the retained
writer-exclusion guard used by both migration and trusted recovery.

Mobile embeddings use `begin_ios_container_migration` or
`begin_android_container_migration` on the corresponding target. The Android
function takes the attached worker's JNI environment and real platform Context;
it obtains package, UID, component and data-directory metadata from the framework.
Neither API accepts a caller-provided container root or a flag to bypass ownership
checks. Hold the identity/session lifecycle guard through the actual blocking
operation and restart, including after the invoking UI task is canceled. An app
that launches additional native relay writers must stop and join those writers
too; the container boundary does not replace ownership of current-process work.

For ingress, validate a complete packet batch before writing anything, then use
`plan_opaque_admission`. Run `Reserved(plan).persist()` on a blocking worker and
commit its returned capability to that same node. Await `Pending` outside the
bounded storage-worker slots. `CommittedDuplicate(check)` is only a plan: call
`check.verify()` on a blocking worker before treating it as durable. Keep the
original typed Link receipt alive through all these operations. A dropped worker
result yields no proof; retry reuses the first complete indexed image.

The private format publishes an immutable object and provenance record, then a
per-TID active index. Unindexed remnants are never served. A durable deletion
intent revokes eligibility before cleanup; restart resumes cleanup. Purge and
maintenance operate on a particular admission path, so a stale plan cannot
delete a later admission of the same TID. Resolve `GetServePlan` and maintenance
plans off the actor; a failed purge intent cannot return an empty success array.

The old-path guard prevents ordinary reopening of that exact legacy directory.
It cannot revoke objects already held in an old process or prevent an old daemon
from using another path or its in-memory fallback. If rolling back software,
keep **both relay hosting and propagation sync disabled**. Preserve the archive,
journal, guard and v2 store; never copy them back to the legacy layout.
