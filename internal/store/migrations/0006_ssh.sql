-- Phase 3: SSH over the mesh.
ALTER TABLE nodes ADD COLUMN ssh_host_key TEXT NOT NULL DEFAULT '';

-- Recorded SSH sessions. Contents live in files under the recordings
-- directory; rows keep who, where and when even if a node is deleted.
CREATE TABLE recordings (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    node_name  TEXT NOT NULL,
    local_user TEXT NOT NULL,
    src_node   TEXT NOT NULL,
    src_user   TEXT NOT NULL,
    started_at INTEGER NOT NULL,
    ended_at   INTEGER NOT NULL,
    size       INTEGER NOT NULL,
    file       TEXT NOT NULL
);
