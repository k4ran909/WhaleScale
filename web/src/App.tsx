import {
  Activity,
  ChevronRight,
  Fingerprint,
  Globe,
  Hourglass,
  KeyRound,
  LockKeyhole,
  LogOut,
  Monitor,
  LifeBuoy,
  Network,
  PanelLeft,
  Search,
  Settings as SettingsIcon,
  Route,
  ScrollText,
  ShieldCheck,
  Smartphone,
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
import { toast } from "./toast";
import { AsciiAquarium } from "@/components/aquarium/ascii-aquarium";
import {
  addPasskey,
  api,
  ApiError,
  authStatus,
  AuthStatus,
  changePassword,
  deletePasskey,
  listPasskeys,
  loginWithAPIKey,
  loginWithPasskey,
  loginWithPassword,
  logout,
  Passkey,
  passkeysSupported,
  setupAdmin,
  twoFactorDisable,
  twoFactorEnable,
  twoFactorSetup,
  twoFactorStatus,
} from "./api";
import { Access, Audit, Flows, Gateway, Keys, Machines, Policy, Recordings, Routes, Topology, Users as UsersPage } from "./pages";
import { ConfirmButton, errText } from "./ui";
import { CommandPalette, Help, Settings } from "./extras";

// The sidebar toggles on Ctrl+B, or Cmd+B on a Mac.
const isMac = typeof navigator !== "undefined" && /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent);

// The console's pages, grouped as the sidebar shows them.
const groups: { label: string; items: { id: string; label: string; about: string; icon: typeof Monitor; view: () => ReactNode }[] }[] = [
  {
    label: "Network",
    items: [
      { id: "machines", label: "Machines", about: "Every device on the mesh; add a device with a join code.", icon: Monitor, view: Machines },
      { id: "topology", label: "Topology", about: "Which machines connect directly and which go through a relay.", icon: Network, view: Topology },
      { id: "flows", label: "Flows", about: "Who talked to whom, on which port, and refused attempts.", icon: Activity, view: Flows },
    ],
  },
  {
    label: "Access",
    items: [
      { id: "users", label: "Users", about: "Users who own machines, and the team who can sign in here.", icon: Users, view: UsersPage },
      { id: "keys", label: "Keys", about: "Pre-auth keys to enroll machines; API keys for automation.", icon: KeyRound, view: Keys },
      { id: "routes", label: "Routes", about: "Approve subnet routes, exit nodes and peer relays.", icon: Route, view: Routes },
      { id: "gateway", label: "Gateway", about: "Approve web apps machines publish on the internet.", icon: Globe, view: Gateway },
      { id: "policy", label: "Access policy", about: "Who may reach what, SSH rules and device limits.", icon: ShieldCheck, view: Policy },
      { id: "access", label: "Access requests", about: "Approve or revoke temporary access.", icon: Hourglass, view: Access },
    ],
  },
  {
    label: "Records",
    items: [
      { id: "recordings", label: "SSH recordings", about: "Recorded SSH sessions: watch or download.", icon: SquareTerminal, view: Recordings },
      { id: "audit", label: "Audit log", about: "Every change anyone made, tamper-evident.", icon: ScrollText, view: Audit },
    ],
  },
  {
    label: "Server",
    items: [
      { id: "settings", label: "Settings", about: "Flow logs, post-quantum, the gateway domain; MagicDNS and SSH status.", icon: SettingsIcon, view: Settings },
      { id: "help", label: "Help", about: "Every guide, linked, and a search.", icon: LifeBuoy, view: HelpPage },
    ],
  },
];

const tabs = groups.flatMap((g) => g.items.map((item) => ({ ...item, group: g.label })));

function HelpPage() {
  return <Help pages={tabs.filter((t) => t.id !== "help")} />;
}

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
  const [tfOpen, setTfOpen] = useState(false);
  const [pkOpen, setPkOpen] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);

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
            {me.method === "admin" && (
              <AnimatedSidebarMenuItem>
                <AnimatedSidebarMenuButton icon={<Smartphone className="size-4" />} onSelect={() => setTfOpen(true)}>
                  Two-factor sign-in
                </AnimatedSidebarMenuButton>
              </AnimatedSidebarMenuItem>
            )}
            {me.method === "admin" && (
              <AnimatedSidebarMenuItem>
                <AnimatedSidebarMenuButton icon={<Fingerprint className="size-4" />} onSelect={() => setPkOpen(true)}>
                  Passkeys
                </AnimatedSidebarMenuButton>
              </AnimatedSidebarMenuItem>
            )}
            <AnimatedSidebarMenuItem>
              <AnimatedSidebarMenuButton
                icon={<LogOut className="size-4" />}
                onSelect={async () => {
                  await logout();
                  setPwOpen(false);
                  setTfOpen(false);
                  setPkOpen(false);
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
          <button type="button" className="search-button ml-auto" onClick={() => setSearchOpen(true)} aria-label="Search">
            <Search aria-hidden="true" className="size-4" />
            <span className="hidden sm:inline">Search</span>
            <kbd className="hidden sm:inline">{isMac ? "⌘K" : "Ctrl K"}</kbd>
          </button>
        </header>
        <CommandPalette open={searchOpen} setOpen={setSearchOpen} pages={tabs} />
        <div className="main">
          {pwOpen && <ChangePassword onClose={() => setPwOpen(false)} />}
          {tfOpen && <TwoFactor onClose={() => setTfOpen(false)} />}
          {pkOpen && <Passkeys onClose={() => setPkOpen(false)} />}
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
  return status.setup ? (
    <Setup onDone={onDone} onTaken={load} />
  ) : (
    <Login oidc={status.oidc} passkeys={status.passkeys && passkeysSupported()} onDone={onDone} />
  );
}

function Card({ children, onSubmit }: { children: ReactNode; onSubmit?: (e: FormEvent) => void }) {
  return (
    <div className="login login-scene">
      <AsciiAquarium />
      <form className="login-card" onSubmit={onSubmit}>
        <div className="brand big">
          <img src="/whale.svg" width={73} height={40} alt="" /> Whalescale
        </div>
        {children}
      </form>
    </div>
  );
}

/** useSubmit runs an async form action with busy state; errors show as
 * toasts. */
function useSubmit(action: () => Promise<void>) {
  const [busy, setBusy] = useState(false);
  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      await action();
    } catch (e2) {
      toast.error(errText(e2));
    } finally {
      setBusy(false);
    }
  };
  return { busy, onSubmit };
}

function Setup({ onDone, onTaken }: { onDone: () => void; onTaken: () => void }) {
  const [code, setCode] = useState("");
  const [name, setName] = useState("");
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const { busy, onSubmit } = useSubmit(async () => {
    if (pw !== pw2) {
      toast.error("The passwords don't match.");
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
      <button className="btn primary block" disabled={busy}>
        {busy ? "Creating…" : "Create account and sign in"}
      </button>
    </Card>
  );
}

function Login({ oidc, passkeys, onDone }: { oidc: boolean; passkeys: boolean; onDone: () => void }) {
  const [pkBusy, setPkBusy] = useState(false);
  const signInWithPasskey = async () => {
    setPkBusy(true);
    try {
      await loginWithPasskey();
      onDone();
    } catch (e) {
      toast.error(errText(e));
    } finally {
      setPkBusy(false);
    }
  };
  const [name, setName] = useState("");
  const [pw, setPw] = useState("");
  const [key, setKey] = useState("");
  const [useKey, setUseKey] = useState(false);
  const [code, setCode] = useState("");
  const [needCode, setNeedCode] = useState(false);
  const { busy, onSubmit } = useSubmit(async () => {
    if (useKey) await loginWithAPIKey(key);
    else {
      try {
        await loginWithPassword(name, pw, needCode ? code : "");
      } catch (e) {
        // The password was right; ask for the authenticator code.
        if (e instanceof ApiError && e.code === "two-factor" && !needCode) {
          setNeedCode(true);
          return;
        }
        throw e;
      }
    }
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
      {passkeys && !useKey && (
        <>
          <button type="button" className={oidc ? "btn block" : "btn primary block"} disabled={pkBusy} onClick={signInWithPasskey}>
            <span className="inline-flex items-center gap-2">
              <Fingerprint aria-hidden="true" className="size-4" /> {pkBusy ? "Waiting for your passkey…" : "Sign in with a passkey"}
            </span>
          </button>
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
          {needCode && (
            <label>
              Code from your authenticator app
              <input
                inputMode="numeric"
                autoComplete="one-time-code"
                placeholder="123 456"
                maxLength={7}
                value={code}
                onChange={(e) => setCode(e.target.value)}
                required
                autoFocus
              />
            </label>
          )}
        </>
      )}
      <button className={oidc || (passkeys && !useKey) ? "btn block" : "btn primary block"} disabled={busy}>
        {busy ? "Signing in…" : "Sign in"}
      </button>
      <button type="button" className="btn ghost small" onClick={() => setUseKey(!useKey)}>
        {useKey ? "Sign in with a password instead" : "Use an API key instead"}
      </button>
      {!useKey && (
        <p className="muted small">
          Forgot your password? On the server run <code>whalescale admins reset-password NAME</code>
          {needCode && (
            <>
              ; lost your phone, <code>whalescale admins reset-2fa NAME</code>
            </>
          )}
          .
        </p>
      )}
    </Card>
  );
}

function ChangePassword({ onClose }: { onClose: () => void }) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const { busy, onSubmit } = useSubmit(async () => {
    await changePassword(current, next);
    toast.success("Password changed. Other browsers signed in as you were signed out.");
    onClose();
  });
  return (
    <form className="secret" onSubmit={onSubmit}>
      <div className="secret-head">
        <strong>Change password</strong>
        <button type="button" className="btn ghost" onClick={onClose}>Close</button>
      </div>
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
    </form>
  );
}

/** TwoFactor turns two-factor sign-in (TOTP) on or off for the signed-in
 * password account. */
function TwoFactor({ onClose }: { onClose: () => void }) {
  const [status, setStatus] = useState<{ available: boolean; enabled: boolean }>();
  const [pw, setPw] = useState("");
  const [code, setCode] = useState("");
  const [setup, setSetup] = useState<{ secret: string; uri: string; qr: string }>();
  useEffect(() => {
    twoFactorStatus().then(setStatus, (e) => {
      toast.error(errText(e));
      onClose();
    });
  }, []);
  const { busy, onSubmit } = useSubmit(async () => {
    if (status?.enabled) {
      await twoFactorDisable(pw, code);
      toast.success("Two-factor sign-in is off. You sign in with your password alone.");
      onClose();
      return;
    } else if (!setup) {
      setSetup(await twoFactorSetup(pw));
    } else {
      await twoFactorEnable(code);
      toast.success("Two-factor sign-in is on. Other browsers signed in as you were signed out.");
      onClose();
      return;
    }
    setPw("");
    setCode("");
  });
  const codeField = (
    <label>
      Code from the app
      <input inputMode="numeric" autoComplete="one-time-code" placeholder="123 456" maxLength={7} value={code} onChange={(e) => setCode(e.target.value)} required />
    </label>
  );
  return (
    <form className="secret" onSubmit={onSubmit}>
      <div className="secret-head">
        <strong>Two-factor sign-in</strong>
        <button type="button" className="btn ghost" onClick={onClose}>Close</button>
      </div>
      {!status ? (
        <p className="muted">Loading…</p>
      ) : status.enabled ? (
        <>
          <p>
            <strong>On.</strong> Signing in takes your password and a code from your authenticator app. To turn it off, confirm both.
          </p>
          <div className="form-grid">
            <label>
              Password
              <input type="password" value={pw} onChange={(e) => setPw(e.target.value)} autoComplete="current-password" required />
            </label>
            {codeField}
            <button className="btn danger" disabled={busy}>{busy ? "Turning off…" : "Turn off"}</button>
          </div>
        </>
      ) : !setup ? (
        <>
          <p>
            Ask for a code from an authenticator app (Google Authenticator, Microsoft Authenticator, 1Password, Authy…) every time you sign in, on top of your
            password. Confirm your password to start.
          </p>
          <div className="form-grid">
            <label>
              Password
              <input type="password" value={pw} onChange={(e) => setPw(e.target.value)} autoComplete="current-password" required />
            </label>
            <button className="btn primary" disabled={busy}>{busy ? "Starting…" : "Set up"}</button>
          </div>
        </>
      ) : (
        <>
          <p>Scan this with your authenticator app, then type the 6-digit code it shows.</p>
          <div className="row" style={{ alignItems: "flex-start", gap: "1.25rem" }}>
            <img src={"data:image/svg+xml;utf8," + encodeURIComponent(setup.qr)} width={180} height={180} alt="QR code for your authenticator app" />
            <div>
              <p className="muted small">Can't scan? Enter this key in the app instead:</p>
              <code className="mono" style={{ wordBreak: "break-all" }}>{setup.secret.replace(/(.{4})/g, "$1 ").trim()}</code>
            </div>
          </div>
          <div className="form-grid">
            {codeField}
            <button className="btn primary" disabled={busy}>{busy ? "Checking…" : "Turn on"}</button>
          </div>
        </>
      )}
    </form>
  );
}

/** deviceName guesses a name for a new passkey from the browser's system. */
function deviceName() {
  const ua = navigator.userAgent;
  if (/iPhone/.test(ua)) return "iPhone";
  if (/iPad/.test(ua)) return "iPad";
  if (/Android/.test(ua)) return "Android phone";
  if (/Mac/.test(ua)) return "Mac";
  if (/Windows/.test(ua)) return "Windows PC";
  if (/Linux/.test(ua)) return "Linux PC";
  return "Passkey";
}

const dateOf = (unix: number) => new Date(unix * 1000).toLocaleDateString(undefined, { dateStyle: "medium" });

/** Passkeys lists, adds and removes the signed-in password account's
 * passkeys. */
function Passkeys({ onClose }: { onClose: () => void }) {
  const [data, setData] = useState<{ available: boolean; passkeys: Passkey[] }>();
  const [name, setName] = useState(deviceName);
  const [pw, setPw] = useState("");
  const load = () =>
    listPasskeys().then(setData, (e) => {
      toast.error(errText(e));
      onClose();
    });
  useEffect(() => {
    load();
  }, []);
  const { busy, onSubmit } = useSubmit(async () => {
    const p = await addPasskey(pw, name.trim());
    toast.success(`Passkey "${p.name}" added. Next time, choose "Sign in with a passkey".`);
    setPw("");
    load();
  });
  const supported = passkeysSupported();
  return (
    <form className="secret" onSubmit={onSubmit}>
      <div className="secret-head">
        <strong>Passkeys</strong>
        <button type="button" className="btn ghost" onClick={onClose}>Close</button>
      </div>
      <p>
        Sign in with this device's fingerprint, face or PIN, or a security key, instead of your password. A passkey only works
        on this server's address, so a look-alike site can't use it, and it replaces the password and the two-factor code.
      </p>
      {!data ? (
        <p className="muted">Loading…</p>
      ) : (
        <>
          {data.passkeys.length > 0 && (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Added</th>
                    <th>Last used</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {data.passkeys.map((p) => (
                    <tr key={p.id}>
                      <td><strong>{p.name}</strong></td>
                      <td>{dateOf(p.created)}</td>
                      <td>{p.lastUsed ? dateOf(p.lastUsed) : <span className="muted">never</span>}</td>
                      <td className="right">
                        <ConfirmButton
                          label="Remove"
                          confirm="Remove passkey?"
                          onConfirm={() =>
                            deletePasskey(p.id).then(
                              () => (toast.success(`Passkey "${p.name}" removed.`), load()),
                              (e) => toast.error(errText(e)),
                            )
                          }
                        />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {!data.available ? (
            <p className="muted">
              Passkeys need the server's <code>public-url</code> to be an <code>https://</code> address.
            </p>
          ) : !supported ? (
            <p className="muted">This browser can't make passkeys. Try a current Chrome, Edge, Firefox or Safari.</p>
          ) : (
            <div className="form-grid">
              <label>
                Name for this passkey
                <input value={name} onChange={(e) => setName(e.target.value)} maxLength={60} required />
              </label>
              <label>
                Your password
                <input type="password" value={pw} onChange={(e) => setPw(e.target.value)} autoComplete="current-password" required />
              </label>
              <button className="btn primary" disabled={busy}>
                {busy ? "Follow your browser's prompt…" : "Add a passkey"}
              </button>
            </div>
          )}
          <p className="muted small">
            Lost a device? Remove its passkey here, or on the server run <code>whalescale admins reset-passkeys NAME</code>.
          </p>
        </>
      )}
    </form>
  );
}

/** Logo is the app icon: the pixel whale on navy (web/public, made by
 * scripts/brand.sh from assets/brand). */
function Logo({ size = 22 }: { size?: number }) {
  return <img src="/favicon.svg" width={size} height={size} alt="" className="block shrink-0" />;
}
