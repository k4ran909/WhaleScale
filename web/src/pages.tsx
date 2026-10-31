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
                  <td>{n.os || "—"}</td>
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
                <td>{u.nodeCount ?? 0}</td>
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
      <div className="row">
        <button
          className="btn"
          onClick={async () => {
            try {
              const r = await api.createAPIKey(90 * 86400);
              setSecret({ title: "New API key", value: r.secret, hint: "Shown only once. Valid for 90 days." });
              apiKeys.reload();
            } catch (err) {
              setMsg(errText(err));
            }
          }}
        >
          Create API key
        </button>
      </div>
      {apiKeys.data && apiKeys.data.length > 0 && (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Key</th>
                <th>Last used</th>
                <th>Expires</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {apiKeys.data.slice().reverse().map((k) => (
                <tr key={k.id} className={k.valid ? "" : "dim"}>
                  <td className="mono">wsapi-{k.prefix}-…</td>
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
