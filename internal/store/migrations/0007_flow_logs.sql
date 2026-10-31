-- Phase 3: flow logs. One row per connection per reporting window, as the
-- reporting node saw it. Pruned after the retention period.
CREATE TABLE flow_logs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    node_name    TEXT NOT NULL,
    proto        INTEGER NOT NULL,
    client       TEXT NOT NULL,
    server       TEXT NOT NULL,
    port         INTEGER NOT NULL,
    outbound     INTEGER NOT NULL,
    denied       INTEGER NOT NULL,
    started_at   INTEGER NOT NULL,
    ended_at     INTEGER NOT NULL,
    bytes_sent   INTEGER NOT NULL,
    bytes_recv   INTEGER NOT NULL,
    packets_sent INTEGER NOT NULL,
    packets_recv INTEGER NOT NULL
);
CREATE INDEX flow_logs_ended ON flow_logs(ended_at);
CREATE INDEX flow_logs_node ON flow_logs(node_name, ended_at);
