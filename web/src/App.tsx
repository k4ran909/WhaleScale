import { FormEvent, ReactNode, useEffect, useState } from "react";
import { api, ApiError, authStatus, AuthStatus, changePassword, loginWithAPIKey, loginWithPassword, logout, setupAdmin } from "./api";
import { Access, Audit, Flows, Gateway, Keys, Machines, Policy, Recordings, Routes, Topology, Users } from "./pages";
import { errText } from "./ui";

const tabs = [
  { id: "machines", label: "Machines", view: Machines },
  { id: "topology", label: "Topology", view: Topology },
  { id: "flows", label: "Flows", view: Flows },
  { id: "users", label: "Users", view: Users },
  { id: "keys", label: "Keys", view: Keys },
  { id: "routes", label: "Routes", view: Routes },
  { id: "gateway", label: "Gateway", view: Gateway },
  { id: "policy", label: "Access policy", view: Policy },
  { id: "access", label: "Access requests", view: Access },
  { id: "recordings", label: "SSH recordings", view: Recordings },
  { id: "audit", label: "Audit log", view: Audit },
] as const;

function currentTab() {
  const id = location.hash.replace(/^#\/?/, "");
  return tabs.find((t) => t.id === id) ?? tabs[0];
}

type Me = { method: string; identity: string; oidcEnabled?: boolean };

export function App() {
  const [me, setMe] = useState<Me | null | undefined>(undefined);
  const [tab, setTab] = useState(currentTab);
  const [pwOpen, setPwOpen] = useState(false);

  useEffect(() => {
    const onHash = () => setTab(currentTab());
    addEventListener("hashchange", onHash);
    return () => removeEventListener("hashchange", onHash);
  }, []);

  const refreshMe = () =>
    api.whoAmI().then(setMe, (e) => {
      if (e instanceof ApiError && e.code === "unauthenticated") setMe(null);
      else setMe(null);
    });
  useEffect(() => {
    refreshMe();
  }, []);

  if (me === undefined) return <div className="boot">Loading…</div>;
  if (me === null) return <SignIn onDone={refreshMe} />;

  const View = tab.view;
  return (
    <div className="shell">
      <aside className="nav">
        <div className="brand">
          <Logo /> Whalescale
        </div>
        <nav>
          {tabs.map((t) => (
            <a key={t.id} href={`#/${t.id}`} className={t.id === tab.id ? "active" : ""} aria-current={t.id === tab.id ? "page" : undefined}>
              {t.label}
            </a>
          ))}
        </nav>
        <div className="me">
          <div className="me-id" title={`${me.method}: ${me.identity}`}>{me.identity}</div>
          {me.method === "admin" && (
            <button className="btn ghost small" onClick={() => setPwOpen(true)}>
              Change password
            </button>
          )}
          <button
            className="btn ghost small"
            onClick={async () => {
              await logout();
              setMe(null);
            }}
          >
            Sign out
          </button>
        </div>
      </aside>
      <main className="main">
        {pwOpen && <ChangePassword onClose={() => setPwOpen(false)} />}
        <View />
      </main>
    </div>
  );
}

/** SignIn shows first-run setup until the server has an admin account, then
 * the sign-in form. */
function SignIn({ onDone }: { onDone: () => void }) {
  const [status, setStatus] = useState<AuthStatus>();
  const [err, setErr] = useState<string>();
  const load = () => authStatus().then(setStatus, (e) => setErr(errText(e)));
  useEffect(() => {
    load();
  }, []);
  if (!status) {
    return (
      <Card>
        <p className={err ? "err-line" : "muted"}>{err ?? "Loading…"}</p>
      </Card>
    );
  }
  return status.setup ? <Setup onDone={onDone} onTaken={load} /> : <Login oidc={status.oidc} onDone={onDone} />;
}

function Card({ children, onSubmit }: { children: ReactNode; onSubmit?: (e: FormEvent) => void }) {
  return (
    <div className="login">
      <form className="login-card" onSubmit={onSubmit}>
        <div className="brand big">
          <Logo /> Whalescale
        </div>
        {children}
      </form>
    </div>
  );
}

/** useSubmit runs an async form action with busy and error state. */
function useSubmit(action: () => Promise<void>) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string>();
  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr(undefined);
    try {
      await action();
    } catch (e2) {
      setErr(errText(e2));
    } finally {
      setBusy(false);
    }
  };
  return { busy, err, setErr, onSubmit };
}

function Setup({ onDone, onTaken }: { onDone: () => void; onTaken: () => void }) {
  const [code, setCode] = useState("");
  const [name, setName] = useState("");
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const { busy, err, setErr, onSubmit } = useSubmit(async () => {
    if (pw !== pw2) {
      setErr("The passwords don't match.");
      return;
    }
    try {
      await setupAdmin(code, name, pw);
    } catch (e) {
      if (e instanceof ApiError && e.code === "409") onTaken(); // someone finished setup meanwhile
      throw e;
    }
    onDone();
  });
  return (
    <Card onSubmit={onSubmit}>
      <h1>Create your admin account</h1>
      <p className="muted">
        This server has no admin yet. The account you create here manages the network; afterwards this page is gone
        for good.
      </p>
      <label>
        Setup code
        <input value={code} onChange={(e) => setCode(e.target.value)} placeholder="ABCD-EFGH" autoComplete="off" required autoFocus />
      </label>
      <p className="muted small">
        The server printed it in its log when it started: look for <code>setup_code</code> (on Dokploy: your app → Logs).
        On the server you can also run <code>whalescale setup-code</code>.
      </p>
      <label>
        Your name
        <input value={name} onChange={(e) => setName(e.target.value)} placeholder="karan" pattern="[a-zA-Z0-9][a-zA-Z0-9-]*" autoComplete="username" required />
      </label>
      <label>
        Password
        <input type="password" value={pw} onChange={(e) => setPw(e.target.value)} minLength={10} autoComplete="new-password" required />
      </label>
      <label>
        Password again
        <input type="password" value={pw2} onChange={(e) => setPw2(e.target.value)} minLength={10} autoComplete="new-password" required />
      </label>
      <p className="muted small">At least 10 characters.</p>
      {err && <div className="err-line">{err}</div>}
      <button className="btn primary block" disabled={busy}>
        {busy ? "Creating…" : "Create account and sign in"}
      </button>
    </Card>
  );
}

function Login({ oidc, onDone }: { oidc: boolean; onDone: () => void }) {
  const [name, setName] = useState("");
  const [pw, setPw] = useState("");
  const [key, setKey] = useState("");
  const [useKey, setUseKey] = useState(false);
  const { busy, err, onSubmit } = useSubmit(async () => {
    if (useKey) await loginWithAPIKey(key);
    else await loginWithPassword(name, pw);
    onDone();
  });
  return (
    <Card onSubmit={onSubmit}>
      <p className="muted">Sign in to manage your network.</p>
      {oidc && (
        <>
          <a className="btn primary block" href="/auth/login">Sign in with your identity provider</a>
          <div className="or"><span>or</span></div>
        </>
      )}
      {useKey ? (
        <label>
          API key
          <input type="password" autoComplete="off" placeholder="wsapi-…" value={key} onChange={(e) => setKey(e.target.value)} required autoFocus />
        </label>
      ) : (
        <>
          <label>
            Name
            <input value={name} onChange={(e) => setName(e.target.value)} autoComplete="username" required autoFocus={!oidc} />
          </label>
          <label>
            Password
            <input type="password" value={pw} onChange={(e) => setPw(e.target.value)} autoComplete="current-password" required />
          </label>
        </>
      )}
      {err && <div className="err-line">{err}</div>}
      <button className={oidc ? "btn block" : "btn primary block"} disabled={busy}>
        {busy ? "Signing in…" : "Sign in"}
      </button>
      <button type="button" className="btn ghost small" onClick={() => setUseKey(!useKey)}>
        {useKey ? "Sign in with a password instead" : "Use an API key instead"}
      </button>
      {!useKey && (
        <p className="muted small">
          Forgot your password? On the server run <code>whalescale admins reset-password NAME</code>.
        </p>
      )}
    </Card>
  );
}

function ChangePassword({ onClose }: { onClose: () => void }) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [done, setDone] = useState(false);
  const { busy, err, onSubmit } = useSubmit(async () => {
    await changePassword(current, next);
    setDone(true);
  });
  return (
    <form className="secret" onSubmit={onSubmit}>
      <div className="secret-head">
        <strong>Change password</strong>
        <button type="button" className="btn ghost" onClick={onClose}>Close</button>
      </div>
      {done ? (
        <p className="ok-line">Password changed. Other browsers signed in as you were signed out.</p>
      ) : (
        <div className="form-grid">
          <label>
            Current password
            <input type="password" value={current} onChange={(e) => setCurrent(e.target.value)} autoComplete="current-password" required />
          </label>
          <label>
            New password (10+ characters)
            <input type="password" value={next} onChange={(e) => setNext(e.target.value)} minLength={10} autoComplete="new-password" required />
          </label>
          <button className="btn primary" disabled={busy}>{busy ? "Saving…" : "Change password"}</button>
        </div>
      )}
      {err && <div className="err-line">{err}</div>}
    </form>
  );
}

function Logo() {
  return (
    <svg width="22" height="22" viewBox="0 0 32 32" aria-hidden="true">
      <rect width="32" height="32" rx="8" fill="var(--accent)" />
      <path d="M6 19c3 0 4-3 7-3s4 3 7 3 4-3 6-3" stroke="white" strokeWidth="2.5" fill="none" strokeLinecap="round" />
    </svg>
  );
}
