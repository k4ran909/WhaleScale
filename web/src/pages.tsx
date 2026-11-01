import { useEffect, useMemo, useRef, useState } from "react";
import { api, Node, PathReport } from "./api";
import { Banner, ConfirmButton, Dot, Empty, Page, SecretBox, errText, timeAgo, timeUntil, useLoad } from "./ui";

// ---------- Machines ----------

export function Machines() {
  const { data: nodes, error, reload } = useLoad(api.listNodes, 10000);
  const [q, setQ] = useState("");
  const [actionErr, setActionErr] = useState<string>();
  const shown = useMemo(() => {
    const s = q.trim().toLowerCase();
    return (nodes ?? []).filter(
      (n) => !s || n.name.includes(s) || n.user.includes(s) || (n.addresses ?? []).some((a) => a.includes(s)),
    );
  }, [nodes, q]);
  const online = (nodes ?? []).filter((n) => n.online).length;

  return (
    <Page
      title="Machines"
      lead={nodes ? `${nodes.length} machines, ${online} online` : undefined}
      actions={<input className="search" placeholder="Filter by name, user or IP" value={q} onChange={(e) => setQ(e.target.value)} />}
    >
      {error && <Banner kind="error">{error}</Banner>}
      {actionErr && <Banner kind="error">{actionErr}</Banner>}
      {nodes && nodes.length === 0 && (
        <Empty>
          No machines yet. Create a key under <a href="#/keys">Keys</a>, then run <code>ws login</code> on a device.
        </Empty>
      )}
      {shown.length > 0 && (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Machine</th>
                <th>Addresses</th>
                <th>User</th>
                <th>OS</th>
                <th>Routes</th>
                <th>Last seen</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {shown.map((n) => (
                <tr key={n.id}>
                  <td>
                    <Dot on={n.online} />
                    <strong>{n.name}</strong>
                    <div className="sub mono">{n.fqdn}</div>
                  </td>
                  <td className="mono">
                    {(n.addresses ?? []).map((a) => (
                      <div key={a}>{a}</div>
                    ))}
                  </td>
                  <td>{n.user}</td>
                  <td>
                    {n.os || "—"} {n.osVersion && <span className="sub">{n.osVersion}</span>}
                    {n.clientVersion && <div className="sub">client {n.clientVersion}</div>}
                  </td>
                  <td>
                    <RouteBadges n={n} />
                  </td>
                  <td>{n.online ? <span className="ok-text">Online</span> : timeAgo(n.lastSeen)}</td>
                  <td className="right">
                    <ConfirmButton
                      label="Remove"
                      confirm="Remove machine?"
                      onConfirm={() => api.deleteNode(n.id).then(reload, (e) => setActionErr(errText(e)))}
                    />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Page>
  );
}

function RouteBadges({ n }: { n: Node }) {
  const pending = (n.advertisedRoutes ?? []).filter(
    (r) => !(n.routes ?? []).includes(r) && !(n.exitNode && (r === "0.0.0.0/0" || r === "::/0")),
  );
  if (!n.routes?.length && !n.exitNode && !pending.length) return <span className="muted">—</span>;
  return (
    <div className="badges">
      {n.exitNode && <span className="badge blue">Exit node</span>}
      {(n.routes ?? []).map((r) => (
        <span key={r} className="badge mono">{r}</span>
      ))}
      {pending.length > 0 && (
        <a className="badge amber" href="#/routes">
          {pending.length} awaiting approval
        </a>
      )}
    </div>
  );
}

// ---------- Topology ----------

export function Topology() {
  const { data: paths, error } = useLoad(api.topology, 10000);
  const { data: nodes } = useLoad(api.listNodes, 10000);
  const names = useMemo(() => (nodes ?? []).filter((n) => n.online).map((n) => n.name).sort(), [nodes]);
  const byPair = useMemo(() => {
    const m = new Map<string, PathReport>();
    for (const p of paths ?? []) m.set(`${p.fromNode}→${p.toNode}`, p);
    return m;
  }, [paths]);
  const counts = { direct: 0, "peer-relay": 0, relay: 0, none: 0 };
  for (const p of paths ?? []) counts[p.path] = (counts[p.path] ?? 0) + 1;

  return (
    <Page
      title="Topology"
      lead="How each online machine reaches each peer, as the machines report it (updated every 30 s)."
    >
      {error && <Banner kind="error">{error}</Banner>}
      <div className="stats">
        <Stat label="Direct paths" value={counts.direct} tone="ok" />
        <Stat label="Peer relay" value={counts["peer-relay"]} tone="ok" />
        <Stat label="Server relay" value={counts.relay} tone="warn" />
        <Stat label="No path" value={counts.none} tone="bad" />
      </div>
      {names.length < 2 ? (
        <Empty>Topology appears once at least two machines are online.</Empty>
      ) : (
        <div className="table-wrap">
          <table className="matrix">
            <thead>
              <tr>
                <th className="corner">from ↓ to →</th>
                {names.map((n) => (
                  <th key={n}>{n}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {names.map((from) => (
                <tr key={from}>
                  <th>{from}</th>
                  {names.map((to) => {
                    if (from === to) return <td key={to} className="self" />;
                    const p = byPair.get(`${from}→${to}`);
                    if (!p) return <td key={to} className="muted center">·</td>;
                    return (
                      <td key={to} className={`cell ${p.path}`} title={p.addr ? `${p.path} via ${p.addr}` : p.path}>
                        <span className="cell-path">{p.path}</span>
                        {(p.path === "direct" || p.path === "peer-relay") && p.latencyMs !== undefined && (
                          <span className="cell-lat">{p.latencyMs.toFixed(1)} ms</span>
                        )}
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <p className="muted small">
        Relayed paths work but add latency. They usually mean both sides are behind strict NAT; run <code>ws netcheck</code> on
        the machine to see its NAT type.
      </p>
    </Page>
  );
}

function Stat(props: { label: string; value: number; tone: "ok" | "warn" | "bad" }) {
  return (
    <div className={`stat ${props.tone}`}>
      <div className="stat-value">{props.value}</div>
      <div className="stat-label">{props.label}</div>
    </div>
  );
}

// ---------- Users ----------

export function Users() {
  const { data: users, error, reload } = useLoad(api.listUsers);
  const [name, setName] = useState("");
  const [msg, setMsg] = useState<{ kind: "error" | "ok"; text: string }>();
  return (
    <Page title="Users" lead="Machines belong to users. Users signing in through OIDC are created automatically.">
      {error && <Banner kind="error">{error}</Banner>}
      {msg && <Banner kind={msg.kind}>{msg.text}</Banner>}
      <form
        className="inline-form"
        onSubmit={async (e) => {
          e.preventDefault();
          try {
            await api.createUser(name.trim());
            setMsg({ kind: "ok", text: `Created user ${name.trim()}.` });
            setName("");
            reload();
          } catch (err) {
            setMsg({ kind: "error", text: errText(err) });
          }
        }}
      >
        <input placeholder="new user name, e.g. karan" value={name} onChange={(e) => setName(e.target.value)} pattern="[a-z0-9][a-z0-9-]*" required />
        <button className="btn primary">Add user</button>
      </form>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Email</th>
              <th>Machines</th>
              <th>Created</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {(users ?? []).map((u) => (
              <tr key={u.id}>
                <td><strong>{u.name}</strong></td>
                <td>{u.email || <span className="muted">—</span>}</td>
                <td>
                  {u.nodeCount ?? 0}
                  {u.deviceLimit !== undefined && (
                    <span className={(u.nodeCount ?? 0) >= u.deviceLimit ? "warn-text" : "sub"}> / {u.deviceLimit}</span>
                  )}
                </td>
                <td>{timeAgo(u.createdAt)}</td>
                <td className="right">
                  <ConfirmButton
                    label="Delete"
                    confirm="Delete user?"
                    onConfirm={() =>
                      api.deleteUser(u.name).then(reload, (err) => setMsg({ kind: "error", text: errText(err) }))
                    }
                  />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Page>
  );
}

// ---------- Keys ----------

const durations: [string, number][] = [
  ["1 hour", 3600],
  ["1 day", 86400],
  ["7 days", 7 * 86400],
  ["90 days", 90 * 86400],
];

export function Keys() {
  const { data: keys, error, reload } = useLoad(api.listPreAuthKeys);
  const { data: users } = useLoad(api.listUsers);
  const apiKeys = useLoad(api.listAPIKeys);
  const [user, setUser] = useState("");
  const [reusable, setReusable] = useState(false);
  const [ephemeral, setEphemeral] = useState(false);
  const [ttl, setTtl] = useState(86400);
  const [secret, setSecret] = useState<{ title: string; value: string; hint: string }>();
  const [msg, setMsg] = useState<string>();
  useEffect(() => {
    if (!user && users?.length) setUser(users[0].name);
  }, [users, user]);

  return (
    <Page title="Keys" lead="Pre-auth keys enroll machines without a browser. API keys sign in to this console and the admin API.">
      {error && <Banner kind="error">{error}</Banner>}
      {msg && <Banner kind="error">{msg}</Banner>}
      {secret && <SecretBox title={secret.title} secret={secret.value} hint={secret.hint} onClose={() => setSecret(undefined)} />}

      <h2>Pre-auth keys</h2>
      <form
        className="card form-grid"
        onSubmit={async (e) => {
          e.preventDefault();
          try {
            const r = await api.createPreAuthKey(user, reusable, ephemeral, ttl);
            setSecret({
              title: `Key for ${user}`,
              value: r.secret,
              hint: "Shown only once. On the device run: WS_AUTHKEY=<key> ws login --server <this server's URL>",
            });
            reload();
          } catch (err) {
            setMsg(errText(err));
          }
        }}
      >
        <label>
          User
          <select value={user} onChange={(e) => setUser(e.target.value)} required>
            {(users ?? []).map((u) => (
              <option key={u.id}>{u.name}</option>
            ))}
          </select>
        </label>
        <label>
          Valid for
          <select value={ttl} onChange={(e) => setTtl(Number(e.target.value))}>
            {durations.map(([l, s]) => (
              <option key={s} value={s}>{l}</option>
            ))}
          </select>
        </label>
        <label className="check">
          <input type="checkbox" checked={reusable} onChange={(e) => setReusable(e.target.checked)} /> Reusable
        </label>
        <label className="check">
          <input type="checkbox" checked={ephemeral} onChange={(e) => setEphemeral(e.target.checked)} /> Ephemeral machines
        </label>
        <button className="btn primary" disabled={!users?.length}>Create key</button>
      </form>
      {keys && keys.length > 0 && (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Key</th>
                <th>User</th>
                <th>Type</th>
                <th>Expires</th>
                <th>Status</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {keys.slice().reverse().map((k) => (
                <tr key={k.id} className={k.valid ? "" : "dim"}>
                  <td className="mono">wskey-{k.prefix}-…</td>
                  <td>{k.user}</td>
                  <td>{[k.reusable ? "reusable" : "one-time", k.ephemeral && "ephemeral"].filter(Boolean).join(", ")}</td>
                  <td>{timeUntil(k.expiresAt)}</td>
                  <td>{k.valid ? <span className="ok-text">Valid</span> : k.used && !k.reusable ? "Used" : "Expired"}</td>
                  <td className="right">
                    {k.valid && (
                      <ConfirmButton label="Revoke" confirm="Revoke key?" onConfirm={() => api.expirePreAuthKey(k.prefix).then(reload)} />
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <h2>API keys</h2>
      <p className="sub">
        Admin keys can do everything. Read-only keys can look but not change anything: use them for monitoring and AI
        agents (<code>ws mcp</code>).
      </p>
      <div className="row">
        {(["admin", "read"] as const).map((scope) => (
          <button
            key={scope}
            className="btn"
            onClick={async () => {
              try {
                const r = await api.createAPIKey(90 * 86400, scope);
                setSecret({
                  title: scope === "read" ? "New read-only API key" : "New API key",
                  value: r.secret,
                  hint: "Shown only once. Valid for 90 days.",
                });
                apiKeys.reload();
              } catch (err) {
                setMsg(errText(err));
              }
            }}
          >
            {scope === "read" ? "Create read-only key" : "Create admin key"}
          </button>
        ))}
      </div>
      {apiKeys.data && apiKeys.data.length > 0 && (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Key</th>
                <th>Scope</th>
                <th>Last used</th>
                <th>Expires</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {apiKeys.data.slice().reverse().map((k) => (
                <tr key={k.id} className={k.valid ? "" : "dim"}>
                  <td className="mono">wsapi-{k.prefix}-…</td>
                  <td>{k.scope === "read" ? "read-only" : "admin"}</td>
                  <td>{k.lastUsed ? timeAgo(k.lastUsed) : "never"}</td>
                  <td>{timeUntil(k.expiresAt)}</td>
                  <td className="right">
                    {k.valid && (
                      <ConfirmButton label="Revoke" confirm="Revoke key?" onConfirm={() => api.expireAPIKey(k.prefix).then(apiKeys.reload)} />
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Page>
  );
}

// ---------- Routes ----------

export function Routes() {
  const { data: routes, error, reload } = useLoad(api.listRoutes, 10000);
  const relays = useLoad(api.listPeerRelays, 10000);
  const [msg, setMsg] = useState<string>();
  const pending = (routes ?? []).filter((r) => !r.approved).length;
  return (
    <Page
      title="Routes"
      lead="Subnet routers and exit nodes advertise routes; nothing is routed until you approve it."
    >
      {error && <Banner kind="error">{error}</Banner>}
      {msg && <Banner kind="error">{msg}</Banner>}
      {pending > 0 && <Banner kind="warn">{pending} route(s) waiting for approval.</Banner>}
      {routes && routes.length === 0 ? (
        <Empty>
          No routes advertised. On a Linux machine on your LAN run <code>ws up --advertise-routes 192.168.1.0/24</code>, or{" "}
          <code>--advertise-exit-node</code>.
        </Empty>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Machine</th>
                <th>Route</th>
                <th>Kind</th>
                <th>Status</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {(routes ?? []).map((r) => (
                <tr key={r.nodeId + r.prefix}>
                  <td><strong>{r.nodeName}</strong></td>
                  <td className="mono">{r.prefix}</td>
                  <td>{r.exitNode ? "Exit node" : "Subnet"}</td>
                  <td>{r.approved ? <span className="ok-text">Approved</span> : <span className="warn-text">Pending</span>}</td>
                  <td className="right">
                    <button
                      className={r.approved ? "btn ghost" : "btn primary"}
                      onClick={() =>
                        api.setRouteApproved(r.nodeId, r.prefix, !r.approved).then(reload, (e) => setMsg(errText(e)))
                      }
                    >
                      {r.approved ? "Disable" : "Approve"}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <h2>Peer relays</h2>
      <p className="muted">
        A well-connected machine (a VPS, or a home server with a port forward) can relay UDP for peers that can't connect
        directly, which is faster than the server's relay. It only ever sees encrypted traffic. Offer one with{" "}
        <code>ws up --relay</code>.
      </p>
      {relays.data && relays.data.length > 0 && (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Machine</th>
                <th>Status</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {relays.data.map((r) => (
                <tr key={r.nodeId}>
                  <td>
                    <Dot on={r.online} />
                    <strong>{r.nodeName}</strong>
                  </td>
                  <td>{r.approved ? <span className="ok-text">Relaying</span> : <span className="warn-text">Offered</span>}</td>
                  <td className="right">
                    <button
                      className={r.approved ? "btn ghost" : "btn primary"}
                      onClick={() => api.setPeerRelayApproved(r.nodeId, !r.approved).then(relays.reload, (e) => setMsg(errText(e)))}
                    >
                      {r.approved ? "Stop" : "Approve"}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Page>
  );
}

// ---------- Policy ----------

export function Policy() {
  const loaded = useLoad(api.getPolicy);
  const [text, setText] = useState<string>();
  const [check, setCheck] = useState<{ errors?: string[]; warnings?: string[] }>();
  const [saved, setSaved] = useState<string>();
  const [saveErr, setSaveErr] = useState<string>();
  const timer = useRef<number>();

  useEffect(() => {
    if (loaded.data && text === undefined) setText(loaded.data.policy);
  }, [loaded.data, text]);

  useEffect(() => {
    if (text === undefined) return;
    window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => {
      api.checkPolicy(text).then(setCheck, (e) => setCheck({ errors: [errText(e)] }));
    }, 400);
    return () => window.clearTimeout(timer.current);
  }, [text]);

  const editable = loaded.data?.editable ?? false;
  const dirty = text !== undefined && text !== loaded.data?.policy;
  const hasErrors = (check?.errors?.length ?? 0) > 0;

  return (
    <Page
      title="Access policy"
      lead={
        <>
          Who may reach what. Without a rule, traffic is dropped by the receiving machine; replies to connections a machine opened
          itself are always allowed. Selectors: <code>*</code>, a user, <code>group:NAME</code>, <code>node:NAME</code>, or a CIDR;
          destinations take <code>:ports</code> (<code>*</code>, <code>22</code>, <code>80-90</code>, <code>22,443</code>).
        </>
      }
      actions={
        editable && (
          <button
            className="btn primary"
            disabled={!dirty || hasErrors}
            onClick={async () => {
              setSaveErr(undefined);
              try {
                const r = await api.setPolicy(text!);
                setSaved(r.warnings?.length ? `Saved with ${r.warnings.length} warning(s).` : "Saved and pushed to all machines.");
                loaded.reload();
                setTimeout(() => setSaved(undefined), 4000);
              } catch (e) {
                setSaveErr(errText(e));
              }
            }}
          >
            Save policy
          </button>
        )
      }
    >
      {loaded.error && <Banner kind="error">{loaded.error}</Banner>}
      {loaded.data?.source === "file" && (
        <Banner kind="warn">This policy comes from a file given with --policy. Edit that file; the server reloads it within 5 s.</Banner>
      )}
      {loaded.data?.source === "url" && (
        <Banner kind={loaded.data.syncError ? "error" : "ok"}>
          Synced from <code>{loaded.data.syncUrl}</code>
          {loaded.data.revision && <> (revision {loaded.data.revision}, checked {timeAgo(loaded.data.lastSync)})</>}. Change
          it in the repository; a push webhook applies it at once.
          {loaded.data.syncError && <> Last sync failed, so the previous policy is still in force: {loaded.data.syncError}</>}
        </Banner>
      )}
      {loaded.data?.source === "default" && <Banner kind="ok">No policy saved yet: every machine can reach every other machine.</Banner>}
      {saved && <Banner kind="ok">{saved}</Banner>}
      {saveErr && <Banner kind="error">{saveErr}</Banner>}
      <textarea
        className="editor"
        spellCheck={false}
        readOnly={!editable}
        value={text ?? ""}
        onChange={(e) => setText(e.target.value)}
        aria-label="Policy JSON"
      />
      <div className="check-results">
        {check?.errors?.map((e) => (
          <div key={e} className="err-line">✘ {e}</div>
        ))}
        {check?.warnings?.map((w) => (
          <div key={w} className="warn-line">! {w}</div>
        ))}
        {check && !hasErrors && !check.warnings?.length && <div className="ok-line">✔ Policy is valid</div>}
      </div>
      <Explain draft={dirty && !hasErrors ? text : undefined} />
      <p className="muted small">
        Add <code>"tests"</code> to pin down intent, for example{" "}
        <code>{'"tests": [{"src": "guest", "accept": ["node:nas:445"], "deny": ["karan:22"]}]'}</code>. A policy that fails its
        tests is not saved.
      </p>
    </Page>
  );
}

function Explain({ draft }: { draft?: string }) {
  const [src, setSrc] = useState("");
  const [dst, setDst] = useState("");
  const [result, setResult] = useState<{ allowed?: boolean; reasons?: string[]; error?: string }>();
  return (
    <div className="card explain">
      <h2>Explain access</h2>
      <form
        className="form-grid"
        onSubmit={async (e) => {
          e.preventDefault();
          try {
            setResult(await api.explainAccess(src.trim(), dst.trim(), draft));
          } catch (err) {
            setResult({ error: errText(err) });
          }
        }}
      >
        <label>
          From
          <input placeholder="user, node:NAME or IP" value={src} onChange={(e) => setSrc(e.target.value)} required />
        </label>
        <label>
          To
          <input placeholder="node:nas:445" value={dst} onChange={(e) => setDst(e.target.value)} required />
        </label>
        <button className="btn">Explain</button>
        {draft && <span className="muted small">using your unsaved edits</span>}
      </form>
      {result?.error && <div className="err-line">{result.error}</div>}
      {result && !result.error && (
        <div className="explain-result">
          <strong className={result.allowed ? "ok-text" : "warn-text"}>{result.allowed ? "Allowed" : "Denied"}</strong>
          <ul>
            {(result.reasons ?? []).map((r) => (
              <li key={r}>{r}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

// ---------- Gateway ----------

export function Gateway() {
  const { data, error, reload } = useLoad(api.listExposures, 10000);
  const [msg, setMsg] = useState<string>();
  const exposures = data?.exposures ?? [];
  const pending = exposures.filter((e) => !e.approved).length;
  return (
    <Page
      title="Gateway"
      lead="Machines can publish a local web service on the internet with automatic HTTPS. Nothing goes live until you approve it."
    >
      {error && <Banner kind="error">{error}</Banner>}
      {msg && <Banner kind="error">{msg}</Banner>}
      {data && !data.domain && (
        <Banner kind="warn">
          The gateway is off. Set <code>gateway-domain</code> (e.g. <code>apps.example.com</code>) in the server config and add a
          wildcard DNS record <code>*.apps.example.com</code> pointing at the server.
        </Banner>
      )}
      {pending > 0 && <Banner kind="warn">{pending} service(s) waiting for approval.</Banner>}
      {data && exposures.length === 0 ? (
        <Empty>
          Nothing published. On a machine, run <code>ws expose 8123 --name ha</code> to publish <code>http://localhost:8123</code>
          {data.domain ? (
            <>
              {" "}at <code>https://ha.{data.domain}</code>
            </>
          ) : null}
          .
        </Empty>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Public address</th>
                <th>Machine</th>
                <th>Local port</th>
                <th>Status</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {exposures.map((e) => (
                <tr key={e.nodeId + e.name}>
                  <td>
                    {e.approved && e.url ? (
                      <a href={e.url} target="_blank" rel="noreferrer noopener" className="mono">
                        {e.url}
                      </a>
                    ) : (
                      <span className="mono">{e.url || e.name}</span>
                    )}
                  </td>
                  <td>
                    <Dot on={e.connected} />
                    {e.nodeName}
                  </td>
                  <td className="mono">{e.port}</td>
                  <td>
                    {!e.approved ? (
                      <span className="warn-text">Pending</span>
                    ) : e.connected ? (
                      <span className="ok-text">Live</span>
                    ) : (
                      <span className="muted">Approved, machine offline</span>
                    )}
                  </td>
                  <td className="right">
                    <button
                      className={e.approved ? "btn ghost" : "btn primary"}
                      onClick={() => api.setExposureApproved(e.nodeId, e.name, !e.approved).then(reload, (err) => setMsg(errText(err)))}
                    >
                      {e.approved ? "Take offline" : "Approve"}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <p className="muted small">
        Approved services are reachable by anyone on the internet. Publish only apps with their own login, or keep them on the
        mesh instead.
      </p>
    </Page>
  );
}

// ---------- SSH recordings ----------

function decodeBase64(b64: string): string {
  const bin = atob(b64);
  const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

// castToText turns an asciinema v2 recording into readable text: the output
// events joined, with terminal escape sequences removed.
function castToText(cast: string): string {
  const out: string[] = [];
  for (const line of cast.split("\n").slice(1)) {
    if (!line.trim()) continue;
    try {
      const ev = JSON.parse(line);
      if (Array.isArray(ev) && ev[1] === "o") out.push(String(ev[2]));
    } catch {
      /* skip malformed lines */
    }
  }
  return out
    .join("")
    .replace(/\x1b\[[0-9;?]*[ -/]*[@-~]/g, "")
    .replace(/\x1b\][^\x07]*(\x07|\x1b\\)/g, "")
    .replace(/\r\n?/g, "\n");
}

function sizeText(s?: string): string {
  const n = Number(s ?? 0);
  return n < 1024 ? `${n} B` : n < 1 << 20 ? `${(n / 1024).toFixed(1)} KB` : `${(n / (1 << 20)).toFixed(1)} MB`;
}

export function Recordings() {
  const { data: recs, error } = useLoad(api.listRecordings, 15000);
  const [view, setView] = useState<{ title: string; text: string }>();
  const [msg, setMsg] = useState<string>();

  const open = async (r: { id: string; nodeName: string; localUser: string }, download: boolean) => {
    try {
      const res = await api.getRecording(r.id);
      const cast = decodeBase64(res.data ?? "");
      if (download) {
        const url = URL.createObjectURL(new Blob([cast], { type: "application/x-asciicast" }));
        const a = document.createElement("a");
        a.href = url;
        a.download = `ssh-${r.nodeName}-${r.localUser}-${r.id}.cast`;
        a.click();
        URL.revokeObjectURL(url);
      } else {
        setView({ title: `${r.localUser}@${r.nodeName}`, text: castToText(cast) });
      }
    } catch (e) {
      setMsg(errText(e));
    }
  };

  return (
    <Page
      title="SSH recordings"
      lead={
        <>
          Sessions on machines running the mesh SSH server, when the policy's ssh rule says <code>"record": true</code>. Only
          output is recorded, never keystrokes. Downloads play with <code>asciinema play</code>.
        </>
      }
    >
      {error && <Banner kind="error">{error}</Banner>}
      {msg && <Banner kind="error">{msg}</Banner>}
      {view && (
        <div className="card recording-view">
          <div className="secret-head">
            <strong>{view.title}</strong>
            <button className="btn ghost" onClick={() => setView(undefined)}>Close</button>
          </div>
          <pre>{view.text || "(no output)"}</pre>
        </div>
      )}
      {recs && recs.length === 0 ? (
        <Empty>No recorded sessions yet.</Empty>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>When</th>
                <th>Who</th>
                <th>Logged in to</th>
                <th>Length</th>
                <th>Size</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {(recs ?? []).map((r) => {
                const secs = r.startedAt && r.endedAt ? Math.round((Date.parse(r.endedAt) - Date.parse(r.startedAt)) / 1000) : 0;
                return (
                  <tr key={r.id}>
                    <td>{timeAgo(r.startedAt)}</td>
                    <td>
                      {r.srcUser} <span className="sub">from {r.srcNode}</span>
                    </td>
                    <td className="mono">
                      {r.localUser}@{r.nodeName}
                    </td>
                    <td>{secs < 60 ? `${secs}s` : `${Math.round(secs / 60)} min`}</td>
                    <td>{sizeText(r.size)}</td>
                    <td className="right">
                      <button className="btn ghost" onClick={() => open(r, false)}>View</button>
                      <button className="btn ghost" onClick={() => open(r, true)}>Download</button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </Page>
  );
}

// ---------- Flows ----------

const protoNames: Record<number, string> = { 1: "icmp", 6: "tcp", 17: "udp", 58: "icmp" };

function bytesText(s?: string): string {
  const n = Number(s ?? 0);
  if (n < 1024) return `${n} B`;
  if (n < 1 << 20) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1 << 30) return `${(n / (1 << 20)).toFixed(1)} MB`;
  return `${(n / (1 << 30)).toFixed(1)} GB`;
}

export function Flows() {
  const [since, setSince] = useState(3600);
  const [deniedOnly, setDeniedOnly] = useState(false);
  const [node, setNode] = useState("");
  const [data, setData] = useState<{ flows: import("./api").Flow[]; enabled: boolean }>();
  const [error, setError] = useState<string>();
  const { data: nodes } = useLoad(api.listNodes);

  useEffect(() => {
    let live = true;
    const load = () =>
      api.queryFlows({ node, sinceSeconds: since, deniedOnly, limit: 500 }).then(
        (d) => live && (setData(d), setError(undefined)),
        (e) => live && setError(errText(e)),
      );
    load();
    const t = setInterval(load, 15000);
    return () => {
      live = false;
      clearInterval(t);
    };
  }, [since, deniedOnly, node]);

  return (
    <Page
      title="Flows"
      lead="Who talked to whom, on which port and how much, as each machine reports it every 30 seconds. Refused attempts show as denied."
      actions={
        <div className="row">
          <select value={node} onChange={(e) => setNode(e.target.value)} aria-label="Reported by">
            <option value="">All machines</option>
            {(nodes ?? []).map((n) => (
              <option key={n.id} value={n.name}>{n.name}</option>
            ))}
          </select>
          <select value={since} onChange={(e) => setSince(Number(e.target.value))} aria-label="Time range">
            <option value={900}>Last 15 min</option>
            <option value={3600}>Last hour</option>
            <option value={86400}>Last day</option>
            <option value={7 * 86400}>Last 7 days</option>
          </select>
          <label className="check">
            <input type="checkbox" checked={deniedOnly} onChange={(e) => setDeniedOnly(e.target.checked)} /> Denied only
          </label>
        </div>
      }
    >
      {error && <Banner kind="error">{error}</Banner>}
      {data && !data.enabled && (
        <Banner kind="warn">
          Flow logs are off. Start the server with <code>flow-logs: true</code> to collect them (kept for{" "}
          <code>flow-log-retention</code>, 7 days by default).
        </Banner>
      )}
      {data && data.flows.length === 0 ? (
        <Empty>No flows in this range.</Empty>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>When</th>
                <th>Reported by</th>
                <th>Client → server</th>
                <th>Proto</th>
                <th>Verdict</th>
                <th>Sent</th>
                <th>Received</th>
              </tr>
            </thead>
            <tbody>
              {(data?.flows ?? []).map((f, i) => (
                <tr key={i}>
                  <td>{timeAgo(f.end)}</td>
                  <td>{f.nodeName}</td>
                  <td className="mono">
                    {f.clientName || f.client} → {f.serverName || f.server}
                    {f.port ? `:${f.port}` : ""}
                    {f.outbound && <span className="sub"> (opened here)</span>}
                  </td>
                  <td>{protoNames[f.proto] ?? f.proto}</td>
                  <td>{f.denied ? <span className="warn-text">Denied</span> : "Allowed"}</td>
                  <td>{bytesText(f.bytesSent)}</td>
                  <td>{bytesText(f.bytesRecv)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Page>
  );
}

export function Audit() {
  const [since, setSince] = useState(7 * 86400);
  const [filter, setFilter] = useState("");
  const [data, setData] = useState<{ events: import("./api").AuditEvent[] }>();
  const [check, setCheck] = useState<import("./api").AuditVerification>();
  const [error, setError] = useState<string>();

  useEffect(() => {
    let live = true;
    api.listAuditEvents({ sinceSeconds: since, limit: 1000 }).then(
      (d) => live && (setData(d), setError(undefined)),
      (e) => live && setError(errText(e)),
    );
    return () => {
      live = false;
    };
  }, [since]);

  const verify = () =>
    api.listAuditEvents({ limit: 1, verify: true }).then(
      (d) => setCheck(d.verification),
      (e) => setError(errText(e)),
    );
  const q = filter.trim().toLowerCase();
  const events = (data?.events ?? []).filter(
    (e) => !q || `${e.actor} ${e.action} ${e.detail ?? ""}`.toLowerCase().includes(q),
  );

  return (
    <Page
      title="Audit log"
      lead="Every change to users, machines, keys, approvals and the access policy, and every console sign-in, with who did it. Entries are hash-chained, so editing or deleting one in the database is detectable."
      actions={
        <div className="row">
          <input placeholder="Filter" value={filter} onChange={(e) => setFilter(e.target.value)} aria-label="Filter" />
          <select value={since} onChange={(e) => setSince(Number(e.target.value))} aria-label="Time range">
            <option value={86400}>Last day</option>
            <option value={7 * 86400}>Last 7 days</option>
            <option value={30 * 86400}>Last 30 days</option>
            <option value={0}>Everything</option>
          </select>
          <button onClick={verify}>Verify chain</button>
        </div>
      }
    >
      {error && <Banner kind="error">{error}</Banner>}
      {check &&
        (check.ok ? (
          <Banner kind="ok">
            Intact: {check.checked ?? 0} entries. Head <code>{(check.headHash ?? "").slice(0, 16)}</code>. Note it
            somewhere else now and then; the chain alone can't show that the newest entries were removed.
          </Banner>
        ) : (
          <Banner kind="error">
            The log has been tampered with: entry {check.brokenAt} doesn't match the chain ({check.checked ?? 0}{" "}
            entries before it are intact).
          </Banner>
        ))}
      {data && events.length === 0 ? (
        <Empty>No events in this range.</Empty>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>When</th>
                <th>Who</th>
                <th>What</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {events.map((e) => (
                <tr key={e.id}>
                  <td title={e.at}>{timeAgo(e.at)}</td>
                  <td className="mono">{e.actor}</td>
                  <td>{e.action}</td>
                  <td className="mono sub">{e.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Page>
  );
}

function forDuration(seconds?: string): string {
  const s = Number(seconds ?? 0);
  if (s % 3600 === 0) return `${s / 3600} h`;
  return `${Math.round(s / 60)} min`;
}

export function Access() {
  const [closed, setClosed] = useState(false);
  const [list, setList] = useState<import("./api").AccessRequest[]>();
  const [error, setError] = useState<string>();
  const load = () =>
    api.listAccessRequests(closed).then(
      (l) => (setList(l), setError(undefined)),
      (e) => setError(errText(e)),
    );
  useEffect(() => {
    load();
    const t = setInterval(load, 10000);
    return () => clearInterval(t);
  }, [closed]);
  const act = (p: Promise<unknown>) => p.then(load, (e) => setError(errText(e)));
  const pending = (list ?? []).filter((r) => r.status === "pending");

  return (
    <Page
      title="Access requests"
      lead={
        <>
          Temporary access people asked for with <code>ws access request</code>, under the policy's{" "}
          <code>access_requests</code> rules. Approved access ends on its own when the time is up.
        </>
      }
      actions={
        <label className="check">
          <input type="checkbox" checked={closed} onChange={(e) => setClosed(e.target.checked)} /> Show past requests
        </label>
      }
    >
      {error && <Banner kind="error">{error}</Banner>}
      {pending.length > 0 && <Banner kind="warn">{pending.length} waiting for a decision.</Banner>}
      {list && list.length === 0 ? (
        <Empty>{closed ? "No requests yet." : "Nothing pending and no active grants."}</Empty>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Machine</th>
                <th>Access</th>
                <th>For</th>
                <th>Reason</th>
                <th>Status</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {(list ?? []).map((r) => {
                const active = r.status === "approved" && !!r.expiresAt && new Date(r.expiresAt) > new Date();
                return (
                  <tr key={r.id}>
                    <td>
                      <strong>{r.nodeName}</strong>
                      <div className="sub">{r.user} · {timeAgo(r.requestedAt)}</div>
                    </td>
                    <td className="mono">{r.dst}</td>
                    <td>{forDuration(r.durationSeconds)}</td>
                    <td>{r.reason || <span className="sub">none given</span>}</td>
                    <td>
                      {r.status === "pending" && <span className="warn-text">Waiting</span>}
                      {active && <span className="ok-text">Active, ends {timeUntil(r.expiresAt)}</span>}
                      {!active && r.status !== "pending" && (
                        <span className="sub">
                          {r.status === "approved" ? "expired" : r.status}
                          {r.decidedBy ? ` by ${r.decidedBy}` : ""}
                        </span>
                      )}
                    </td>
                    <td className="actions">
                      {r.status === "pending" && (
                        <>
                          <button className="btn primary" onClick={() => act(api.decideAccess(r.id, true))}>
                            Approve
                          </button>{" "}
                          <button className="btn ghost" onClick={() => act(api.decideAccess(r.id, false))}>
                            Deny
                          </button>
                        </>
                      )}
                      {active && (
                        <ConfirmButton label="Revoke" confirm="Revoke now?" onConfirm={() => act(api.revokeAccess(r.id))} />
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </Page>
  );
}
