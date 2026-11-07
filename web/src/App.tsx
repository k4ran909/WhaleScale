import {
  Activity,
  ChevronRight,
  Globe,
  Hourglass,
  KeyRound,
  LockKeyhole,
  LogOut,
  Monitor,
  Network,
  PanelLeft,
  Route,
  ScrollText,
  ShieldCheck,
  SquareTerminal,
  Users,
  X,
} from "lucide-react";
import { FormEvent, ReactNode, useEffect, useState } from "react";
import {
  AnimatedSidebar,
  AnimatedSidebarClose,
  AnimatedSidebarContent,
  AnimatedSidebarFooter,
  AnimatedSidebarGroup,
  AnimatedSidebarGroupContent,
  AnimatedSidebarGroupLabel,
  AnimatedSidebarHeader,
  AnimatedSidebarInset,
  AnimatedSidebarMenu,
  AnimatedSidebarMenuButton,
  AnimatedSidebarMenuItem,
  AnimatedSidebarProvider,
  AnimatedSidebarRail,
  AnimatedSidebarTrigger,
} from "@/components/ui/animated-sidebar";
import { AsciiAquarium } from "@/components/aquarium/ascii-aquarium";
import { api, ApiError, authStatus, AuthStatus, changePassword, loginWithAPIKey, loginWithPassword, logout, setupAdmin } from "./api";
import { Access, Audit, Flows, Gateway, Keys, Machines, Policy, Recordings, Routes, Topology, Users as UsersPage } from "./pages";
import { errText } from "./ui";

// The sidebar toggles on Ctrl+B, or Cmd+B on a Mac.
const isMac = typeof navigator !== "undefined" && /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent);

// The console's pages, grouped as the sidebar shows them.
const groups = [
  {
    label: "Network",
    items: [
      { id: "machines", label: "Machines", icon: Monitor, view: Machines },
      { id: "topology", label: "Topology", icon: Network, view: Topology },
      { id: "flows", label: "Flows", icon: Activity, view: Flows },
    ],
  },
  {
    label: "Access",
    items: [
      { id: "users", label: "Users", icon: Users, view: UsersPage },
      { id: "keys", label: "Keys", icon: KeyRound, view: Keys },
      { id: "routes", label: "Routes", icon: Route, view: Routes },
      { id: "gateway", label: "Gateway", icon: Globe, view: Gateway },
      { id: "policy", label: "Access policy", icon: ShieldCheck, view: Policy },
      { id: "access", label: "Access requests", icon: Hourglass, view: Access },
    ],
  },
  {
    label: "Records",
    items: [
      { id: "recordings", label: "SSH recordings", icon: SquareTerminal, view: Recordings },
      { id: "audit", label: "Audit log", icon: ScrollText, view: Audit },
    ],
  },
];

const tabs = groups.flatMap((g) => g.items.map((item) => ({ ...item, group: g.label })));

function currentTab() {
  const id = location.hash.replace(/^#\/?/, "");
  return tabs.find((t) => t.id === id) ?? tabs[0];
}

type Me = { method: string; identity: string; oidcEnabled?: boolean };

/** initials for the avatar: "karan" -> "KA", "ann@example.com" -> "AN". */
function initials(identity: string) {
  const name = identity.replace(/^api-key:/, "").split("@")[0];
  return (name.slice(0, 2) || "?").toUpperCase();
}

const methodLabel: Record<string, string> = { admin: "Admin account", oidc: "Signed in with OIDC", "api-key": "API key" };

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
    <AnimatedSidebarProvider>
      <AnimatedSidebar ariaLabel="Whalescale" collapsible="icon">
        <AnimatedSidebarHeader className="p-3 pb-2">
          <div className="flex min-h-11 items-center gap-3 overflow-hidden px-2">
            <span className="grid size-7 shrink-0 place-items-center">
              <Logo size={28} />
            </span>
            <div className="min-w-0 flex-1 group-data-[state=collapsed]/sidebar:hidden">
              <div className="truncate text-sm font-semibold text-foreground">Whalescale</div>
              <div className="truncate text-xs text-muted-foreground">{location.host}</div>
            </div>
            <AnimatedSidebarClose className="ml-auto text-muted-foreground hover:bg-muted md:hidden">
              <X aria-hidden="true" className="size-4" />
            </AnimatedSidebarClose>
          </div>
        </AnimatedSidebarHeader>

        <AnimatedSidebarContent className="px-2 pt-1">
          {groups.map((g) => (
            <AnimatedSidebarGroup key={g.label}>
              <AnimatedSidebarGroupLabel>{g.label}</AnimatedSidebarGroupLabel>
              <AnimatedSidebarGroupContent>
                <AnimatedSidebarMenu>
                  {g.items.map(({ id, label, icon: Icon }) => (
                    <AnimatedSidebarMenuItem key={id}>
                      <AnimatedSidebarMenuButton href={`#/${id}`} isActive={id === tab.id} icon={<Icon className="size-4" />}>
                        {label}
                      </AnimatedSidebarMenuButton>
                    </AnimatedSidebarMenuItem>
                  ))}
                </AnimatedSidebarMenu>
              </AnimatedSidebarGroupContent>
            </AnimatedSidebarGroup>
          ))}
        </AnimatedSidebarContent>

        <AnimatedSidebarFooter className="gap-1 p-3">
          <div className="flex min-h-11 items-center gap-3 overflow-hidden rounded-xl p-1" title={`${me.method}: ${me.identity}`}>
            <span className="grid size-9 shrink-0 place-items-center rounded-full bg-[#d5ff66] text-xs font-semibold text-[#172000]">
              {initials(me.identity)}
            </span>
            <span className="min-w-0 flex-1 group-data-[state=collapsed]/sidebar:hidden">
              <span className="block truncate text-sm font-medium text-foreground">{me.identity}</span>
              <span className="block truncate text-xs text-muted-foreground">{methodLabel[me.method] ?? me.method}</span>
            </span>
          </div>
          <AnimatedSidebarMenu>
            {me.method === "admin" && (
              <AnimatedSidebarMenuItem>
                <AnimatedSidebarMenuButton icon={<LockKeyhole className="size-4" />} onSelect={() => setPwOpen(true)}>
                  Change password
                </AnimatedSidebarMenuButton>
              </AnimatedSidebarMenuItem>
            )}
            <AnimatedSidebarMenuItem>
              <AnimatedSidebarMenuButton
                icon={<LogOut className="size-4" />}
                onSelect={async () => {
                  await logout();
                  setMe(null);
                }}
              >
                Sign out
              </AnimatedSidebarMenuButton>
            </AnimatedSidebarMenuItem>
          </AnimatedSidebarMenu>
        </AnimatedSidebarFooter>

        <AnimatedSidebarRail />
      </AnimatedSidebar>

      <AnimatedSidebarInset>
        <header className="sticky top-0 z-10 flex h-14 shrink-0 items-center gap-3 border-b border-border bg-background/85 px-4 backdrop-blur">
          <AnimatedSidebarTrigger className="text-muted-foreground transition-colors hover:bg-muted hover:text-foreground">
            <PanelLeft aria-hidden="true" className="size-4" />
          </AnimatedSidebarTrigger>
          <div className="h-5 w-px bg-border" />
          <nav aria-label="Breadcrumb" className="flex min-w-0 items-center gap-1.5 text-sm">
            <span className="text-muted-foreground">{tab.group}</span>
            <ChevronRight aria-hidden="true" className="size-3.5 shrink-0 text-muted-foreground" />
            <span className="truncate font-medium text-foreground">{tab.label}</span>
          </nav>
          <kbd className="ml-auto hidden rounded-md border border-border px-1.5 py-0.5 font-sans text-[11px] text-muted-foreground sm:block">
            {isMac ? "⌘B" : "Ctrl B"}
          </kbd>
        </header>
        <div className="main">
          {pwOpen && <ChangePassword onClose={() => setPwOpen(false)} />}
          <View />
        </div>
      </AnimatedSidebarInset>
    </AnimatedSidebarProvider>
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
    <div className="login login-scene">
      <AsciiAquarium />
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

function Logo({ size = 22 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden="true">
      <rect width="32" height="32" rx="8" fill="var(--accent)" />
      <path d="M6 19c3 0 4-3 7-3s4 3 7 3 4-3 6-3" stroke="var(--accent-text)" strokeWidth="2.5" fill="none" strokeLinecap="round" />
    </svg>
  );
}
