import { useEffect, useState } from "react";
import { api, ApiError, loginWithAPIKey, logout } from "./api";
import { Gateway, Keys, Machines, Policy, Routes, Topology, Users } from "./pages";
import { errText } from "./ui";

const tabs = [
  { id: "machines", label: "Machines", view: Machines },
  { id: "topology", label: "Topology", view: Topology },
  { id: "users", label: "Users", view: Users },
  { id: "keys", label: "Keys", view: Keys },
  { id: "routes", label: "Routes", view: Routes },
  { id: "gateway", label: "Gateway", view: Gateway },
  { id: "policy", label: "Access policy", view: Policy },
] as const;

function currentTab() {
  const id = location.hash.replace(/^#\/?/, "");
  return tabs.find((t) => t.id === id) ?? tabs[0];
}

type Me = { method: string; identity: string; oidcEnabled?: boolean };

export function App() {
  const [me, setMe] = useState<Me | null | undefined>(undefined);
  const [tab, setTab] = useState(currentTab);

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
  if (me === null) return <Login onDone={refreshMe} />;

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
          <div className="me-id" title={me.identity}>{me.identity}</div>
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
        <View />
      </main>
    </div>
  );
}

function Login({ onDone }: { onDone: () => void }) {
  const [key, setKey] = useState("");
  const [err, setErr] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [oidc, setOidc] = useState(false);

  // Whether OIDC is on is only visible after sign-in, so probe the endpoint:
  // it redirects when configured and answers 404 when not.
  useEffect(() => {
    fetch("/auth/login", { redirect: "manual" }).then(
      (r) => setOidc(r.type === "opaqueredirect" || r.status === 302),
      () => setOidc(false),
    );
  }, []);

  return (
    <div className="login">
      <form
        className="login-card"
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          setErr(undefined);
          try {
            await loginWithAPIKey(key);
            onDone();
          } catch (e2) {
            setErr(errText(e2));
          } finally {
            setBusy(false);
          }
        }}
      >
        <div className="brand big">
          <Logo /> Whalescale
        </div>
        <p className="muted">Sign in to manage your network.</p>
        {oidc && (
          <>
            <a className="btn primary block" href="/auth/login">Sign in with your identity provider</a>
            <div className="or"><span>or</span></div>
          </>
        )}
        <label>
          API key
          <input
            type="password"
            autoComplete="off"
            placeholder="wsapi-…"
            value={key}
            onChange={(e) => setKey(e.target.value)}
            required
          />
        </label>
        {err && <div className="err-line">{err}</div>}
        <button className={oidc ? "btn block" : "btn primary block"} disabled={busy}>
          {busy ? "Signing in…" : "Sign in with API key"}
        </button>
        <p className="muted small">
          Create one on the server with <code>whalescale apikeys create</code>.
        </p>
      </form>
    </div>
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
