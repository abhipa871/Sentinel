# Security boundary

Repository content is hostile data. Intake does not run hooks, initialize submodules or LFS,
install packages, import modules, execute project commands, or follow symlinks. Public GitHub input
uses read-only API endpoints and pins a full commit SHA before downloading bounded blobs.

Deep Agents receive no host shell, outbound HTTP, broad filesystem, credentials, approval tool, or
write tool. Source spans are limited to 300 lines and verified against the snapshot hash. Large or
binary assets remain metadata-only.

Source writes require a separately authenticated acceptance and gateway authorization. Path
traversal, symlinks, digest drift, commit drift, scope expansion, expired approval, rejected/deferred
proposals, and disabled writes fail closed.

The local memory store and development identity headers are not production controls. Production
must use PostgreSQL RLS, OIDC/session authentication, a secret manager, encrypted object storage,
durable agent checkpoints, isolated scanner/sandbox workers, and an outbox-backed audit stream.

