-- Phase 4: network lock. The server keeps what admins sign on their own
-- machines: every version of the trusted key list, and signatures over
-- node keys. Both are protobuf-encoded (LockState, NodeSignature).
CREATE TABLE lock_chain (
    version INTEGER PRIMARY KEY,
    state   BLOB NOT NULL
);
CREATE TABLE lock_signatures (
    node_key  TEXT PRIMARY KEY,
    signature BLOB NOT NULL
);
