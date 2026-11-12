import { ExternalLink, Search } from "lucide-react";
import { ReactNode, useEffect, useMemo, useRef, useState } from "react";
import { api, Setting, SettingsInfo } from "./api";
import { toast } from "./toast";
import { ConfirmButton, Dot, Page, SecretBox, errText, timeAgo, useLoad } from "./ui";

// ---------- documentation links ----------

const docsBase = "https://github.com/k4ran909/WhaleScale/blob/main/docs/";

/** doc links a page of the documentation on GitHub, with an optional
 * heading anchor. */
export function doc(path: string, anchor?: string) {
  return docsBase + path + (anchor ? "#" + anchor : "");
}

/** DocLink opens a documentation page in a new tab. */
export function DocLink(props: { path: string; anchor?: string; children: ReactNode }) {
  return (
    <a href={doc(props.path, props.anchor)} target="_blank" rel="noreferrer noopener" className="doc-link">
      {props.children}
      <ExternalLink aria-hidden="true" className="ext" />
    </a>
  );
}

export interface HelpTopic {
  title: string;
  about: string;
  path: string;
  anchor?: string;
  group: string;
}

/** The documentation, as the Help page and the search palette list it. */
export const helpTopics: HelpTopic[] = [
  { group: "Start here", title: "Getting started", about: "A server, an admin account and your first devices in ten minutes.", path: "getting-started.md" },
  { group: "Start here", title: "All documentation", about: "The index of every guide.", path: "README.md" },
  { group: "Install the server", title: "Linux", about: "One command on a Linux server, with automatic HTTPS.", path: "install/linux.md" },
  { group: "Install the server", title: "Docker", about: "Run the server in a container.", path: "install/docker.md" },
  { group: "Install the server", title: "Dokploy", about: "Deploy on Dokploy.", path: "install/dokploy.md" },
  { group: "Install the server", title: "Kubernetes", about: "The Helm chart.", path: "install/kubernetes.md" },
  { group: "Use it", title: "Devices", about: "Add Windows, macOS, Linux and Android machines; join codes.", path: "guides/devices.md" },
  { group: "Use it", title: "Android app", about: "The phone app and its signed APK.", path: "guides/android.md" },
  { group: "Use it", title: "The web console", about: "Signing in, passkeys and two-factor sign-in.", path: "guides/console.md" },
  { group: "Use it", title: "Passkeys", about: "Sign in to the console without a password.", path: "guides/console.md", anchor: "passkeys" },
  { group: "Use it", title: "Access policy", about: "Who may reach what: ACLs, groups, tags, SSH rules and device limits.", path: "guides/access-policy.md" },
  { group: "Use it", title: "SSH", about: "The mesh SSH server, who may log in, and session recording.", path: "guides/ssh.md" },
  { group: "Use it", title: "Gateway", about: "Publish a machine's web app on the internet with HTTPS.", path: "guides/gateway.md" },
  { group: "Networking", title: "Networking", about: "Direct paths, relays, MagicDNS and NAT traversal.", path: "guides/networking.md" },
  { group: "Networking", title: "Subnet routers", about: "Reach a whole LAN through one machine.", path: "guides/networking.md", anchor: "subnet-routers" },
  { group: "Networking", title: "Exit nodes", about: "Send all of a machine's internet traffic through another.", path: "guides/networking.md", anchor: "exit-nodes" },
  { group: "Networking", title: "Relays and hard NATs", about: "Why some machines can't connect directly, and what helps.", path: "guides/networking.md", anchor: "relays-and-hard-nats" },
  { group: "Networking", title: "Peer relays", about: "A machine of yours relays for others, faster than the server.", path: "guides/networking.md", anchor: "peer-relays" },
  { group: "Security", title: "Security", about: "Network lock, post-quantum protection and the audit log.", path: "guides/security.md" },
  { group: "Security", title: "Post-quantum protection", about: "ML-KEM keys on top of WireGuard.", path: "guides/security.md", anchor: "post-quantum-protection" },
  { group: "Security", title: "Network lock", about: "Only machines you signed may join.", path: "guides/security.md", anchor: "network-lock" },
  { group: "Operate", title: "Flow logs and monitoring", about: "Connection logs, metrics and alerts.", path: "guides/monitoring.md" },
  { group: "Operate", title: "Automation", about: "API keys, the admin API, the MCP server and Terraform.", path: "guides/automation.md" },
  { group: "Operate", title: "High availability", about: "Several servers sharing one PostgreSQL database.", path: "guides/high-availability.md" },
  { group: "Reference", title: "Architecture", about: "How the pieces fit together.", path: "reference/architecture.md" },
  { group: "Reference", title: "Known gaps", about: "What isn't done yet.", path: "reference/known-gaps.md" },
  { group: "Reference", title: "Security review", about: "Findings and fixes.", path: "reference/security-review.md" },
];

// ---------- switch ----------

function Switch(props: { on: boolean; label: string; disabled?: boolean; onChange: (on: boolean) => void }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={props.on}
      aria-label={props.label}
      disabled={props.disabled}
      className={`switch${props.on ? " on" : ""}`}
      onClick={() => props.onChange(!props.on)}
    >
      <span className="knob" />
    </button>
  );
}

// ---------- Settings ----------

function find(settings: Setting[], name: string): Setting {
  return settings.find((s) => s.name === name) ?? { name };
}

/** Source says where a setting's value comes from, with a way back to the
 * config file's value. */
function Source(props: { s: Setting; busy: boolean; onUseConfig: () => void }) {
  const { s } = props;
  if (!s.fromConsole) return <span className="sub">From the server config file.</span>;
  const conf = s.configValue === "true" ? "on" : s.configValue === "false" || !s.configValue ? "off" : s.configValue;
  return (
    <span className="sub">
      Changed in the console.{" "}
      <button type="button" className="linkish" disabled={props.busy} onClick={props.onUseConfig}>
        Use the config file's value ({conf})
      </button>
    </span>
  );
}

export function Settings() {
  const [info, setInfo] = useState<SettingsInfo>();
  const { data: nodes } = useLoad(api.listNodes, 15000);
  const [busy, setBusy] = useState(false);
  const [domain, setDomain] = useState("");

  const load = () =>
    api.getSettings().then((i) => {
      setInfo(i);
      setDomain(find(i.settings, "gateway-domain").value ?? "");
    }, (e) => toast.error(errText(e)));
  useEffect(() => {
    load();
  }, []);

  const save = async (name: string, value: string, useConfig = false, done?: string) => {
    setBusy(true);
    try {
      const settings = await api.updateSetting(name, value, useConfig);
      setInfo((i) => (i ? { ...i, settings } : i));
      if (name === "gateway-domain") setDomain(find(settings, name).value ?? "");
      toast.success(done ?? "Saved.");
    } catch (e) {
      toast.error(errText(e));
    } finally {
      setBusy(false);
    }
  };

  if (!info) return <Page title="Settings">{null}</Page>;
  const flow = find(info.settings, "flow-logs");
  const pq = find(info.settings, "post-quantum");
  const gw = find(info.settings, "gateway-domain");
  const sshMachines = (nodes ?? []).filter((n) => n.sshHostKey);
  const sshOnline = sshMachines.filter((n) => n.online).length;

  return (
    <Page title="Settings" lead="Changes apply to every machine within seconds. No config file or restart needed.">
      <h2 className="section-title">Features</h2>
      <div className="settings">
        <div className="setting">
          <div className="setting-text">
            <strong>Flow logs</strong>
            <span>
              Machines report who talked to whom, on which port, and refused attempts. See them on{" "}
              <a href="#/flows">Flows</a>. <DocLink path="guides/monitoring.md" anchor="flow-logs">Learn more</DocLink>
            </span>
            <Source s={flow} busy={busy} onUseConfig={() => save("flow-logs", "", true, "Flow logs follow the config file again.")} />
          </div>
          <Switch
            label="Flow logs"
            on={flow.value === "true"}
            disabled={busy}
            onChange={(on) => save("flow-logs", String(on), false, on ? "Flow logs on." : "Flow logs off.")}
          />
        </div>

        <div className="setting">
          <div className="setting-text">
            <strong>Post-quantum protection</strong>
            <span>
              Machines add ML-KEM-768 keys to WireGuard, rotated every 2 minutes, against future quantum computers.{" "}
              <DocLink path="guides/security.md" anchor="post-quantum-protection">Learn more</DocLink>
            </span>
            <Source s={pq} busy={busy} onUseConfig={() => save("post-quantum", "", true, "Post-quantum follows the config file again.")} />
          </div>
          <Switch
            label="Post-quantum protection"
            on={pq.value === "true"}
            disabled={busy}
            onChange={(on) => save("post-quantum", String(on), false, on ? "Post-quantum protection on." : "Post-quantum protection off.")}
          />
        </div>

        <div className="setting column">
          <div className="setting-text">
            <strong>
              Gateway <Dot on={!!gw.value} label={gw.value ? "On" : "Off"} />
            </strong>
            <span>
              Publish a machine's web app at <code>https://NAME.{gw.value || "your-domain"}</code>, approved on the{" "}
              <a href="#/gateway">Gateway</a> page. <DocLink path="guides/gateway.md">Learn more</DocLink>
            </span>
            <Source s={gw} busy={busy} onUseConfig={() => save("gateway-domain", "", true, "The gateway follows the config file again.")} />
          </div>
          <form
            className="inline-form"
            onSubmit={(e) => {
              e.preventDefault();
              save("gateway-domain", domain, false, domain.trim() ? `Gateway on at *.${domain.trim().toLowerCase()}.` : "Gateway off.");
            }}
          >
            <input placeholder="apps.example.com" value={domain} onChange={(e) => setDomain(e.target.value)} aria-label="Gateway domain" />
            <button className="btn primary" disabled={busy || domain.trim().toLowerCase() === (gw.value ?? "")}>
              {gw.value ? "Change" : "Turn on"}
            </button>
            {gw.value && (
              <button type="button" className="btn ghost" disabled={busy} onClick={() => save("gateway-domain", "", false, "Gateway off.")}>
                Turn off
              </button>
            )}
          </form>
          {domain.trim() && (
            <p className="sub">
              Your DNS needs a wildcard record <code>*.{domain.trim().toLowerCase()}</code> pointing at this server ({location.hostname}).
            </p>
          )}
        </div>
      </div>

      <h2 className="section-title">Status</h2>
      <div className="settings">
        <div className="setting">
          <div className="setting-text">
            <strong>
              MagicDNS <Dot on label="On" />
            </strong>
            <span>
              Every machine is reachable by name at <code>NAME.{info.dnsSuffix}</code>, from any other machine on the mesh.{" "}
              <DocLink path="guides/networking.md">Learn more</DocLink>
            </span>
          </div>
        </div>
        <div className="setting">
          <div className="setting-text">
            <strong>
              SSH <Dot on={sshMachines.length > 0 && info.sshRules > 0} label={sshMachines.length > 0 && info.sshRules > 0 ? "In use" : "Not set up"} />
            </strong>
            <span>
              {sshMachines.length} machine{sshMachines.length === 1 ? "" : "s"} run{sshMachines.length === 1 ? "s" : ""} the mesh SSH server
              {sshMachines.length > 0 ? ` (${sshOnline} online)` : ""}; the <a href="#/policy">access policy</a> has {info.sshRules} SSH rule
              {info.sshRules === 1 ? "" : "s"}, {info.sshRecordedRules} of them recording sessions (see{" "}
              <a href="#/recordings">SSH recordings</a>). <DocLink path="guides/ssh.md">Learn more</DocLink>
            </span>
            {sshMachines.length > 0 && <span className="sub">{sshMachines.map((n) => n.name).join(", ")}</span>}
          </div>
        </div>
      </div>
    </Page>
  );
}

// ---------- Team (console accounts) ----------

/** Team lists who can sign in to this console and adds or removes them. */
export function Team(props: { onChange?: () => void }) {
  const { data, reload } = useLoad(api.listConsoleAccounts);
  const [name, setName] = useState("");
  const [secret, setSecret] = useState<{ name: string; password: string }>();
  return (
    <section className="team">
      <h2 className="section-title">Team</h2>
      <p className="muted">
        People who can sign in to this console and manage the network. Each also gets a user of the same name for their own
        machines.
      </p>
      {secret && (
        <SecretBox
          title={`${secret.name}'s password`}
          secret={secret.password}
          hint={
            <>
              Give it to {secret.name} privately; it's shown only once. They sign in at <code>{location.origin}</code> with the name{" "}
              <code>{secret.name}</code>, then change it (and can add a passkey) from the sidebar.
            </>
          }
          onClose={() => setSecret(undefined)}
        />
      )}
      <form
        className="inline-form"
        onSubmit={async (e) => {
          e.preventDefault();
          try {
            const r = await api.createConsoleAccount(name.trim().toLowerCase());
            setSecret({ name: r.account.name, password: r.password });
            setName("");
            reload();
            props.onChange?.();
          } catch (err) {
            toast.error(errText(err));
          }
        }}
      >
        <input placeholder="team member's name, e.g. priya" value={name} onChange={(e) => setName(e.target.value)} pattern="[a-zA-Z0-9][a-zA-Z0-9\-]*" required />
        <button className="btn primary">Add team member</button>
      </form>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Sign-in</th>
              <th>Added</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {(data?.accounts ?? []).map((a) => (
              <tr key={a.name}>
                <td>
                  <strong>{a.name}</strong>
                  {a.name === data?.you && <span className="sub"> (you)</span>}
                </td>
                <td className="sub">
                  Password{a.twoFactor ? " + two-factor code" : ""}
                  {a.passkeys ? `, ${a.passkeys} passkey${a.passkeys === 1 ? "" : "s"}` : ""}
                </td>
                <td>{timeAgo(a.createdAt)}</td>
                <td className="right">
                  {a.name !== data?.you && (
                    <ConfirmButton
                      label="Remove"
                      confirm={`Remove ${a.name}?`}
                      onConfirm={() =>
                        api.deleteConsoleAccount(a.name).then(
                          () => (toast.success(`${a.name} can no longer sign in.`), reload()),
                          (err) => toast.error(errText(err)),
                        )
                      }
                    />
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

// ---------- Help ----------

export function Help(props: { pages: { id: string; label: string; about: string }[] }) {
  const [q, setQ] = useState("");
  const match = (s: string) => s.toLowerCase().includes(q.trim().toLowerCase());
  const topics = helpTopics.filter((t) => match(t.title) || match(t.about) || match(t.group));
  const pages = props.pages.filter((p) => match(p.label) || match(p.about));
  const groups = [...new Set(topics.map((t) => t.group))];
  return (
    <Page
      title="Help"
      lead={
        <>
          Every guide in one place. Press <kbd>{isMac ? "⌘" : "Ctrl"} K</kbd> anywhere to search pages, settings and these guides.
        </>
      }
    >
      <div className="inline-form">
        <input autoFocus placeholder="Search the help…" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search the help" />
      </div>
      {pages.length > 0 && (
        <>
          <h2 className="section-title">Console pages</h2>
          <div className="help-grid">
            {pages.map((p) => (
              <a key={p.id} href={`#/${p.id}`} className="help-card">
                <strong>{p.label}</strong>
                <span>{p.about}</span>
              </a>
            ))}
          </div>
        </>
      )}
      {groups.map((g) => (
        <div key={g}>
          <h2 className="section-title">{g}</h2>
          <div className="help-grid">
            {topics
              .filter((t) => t.group === g)
              .map((t) => (
                <a key={t.title} href={doc(t.path, t.anchor)} target="_blank" rel="noreferrer noopener" className="help-card">
                  <strong>
                    {t.title} <ExternalLink aria-hidden="true" className="ext" />
                  </strong>
                  <span>{t.about}</span>
                </a>
              ))}
          </div>
        </div>
      ))}
      {pages.length === 0 && topics.length === 0 && <p className="muted">Nothing matches “{q}”.</p>}
    </Page>
  );
}

// ---------- search palette (Ctrl+K) ----------

export const isMac = typeof navigator !== "undefined" && /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent);

interface Command {
  label: string;
  hint: string;
  keywords?: string;
  run: () => void;
}

/** CommandPalette opens on Ctrl+K (Cmd+K on a Mac), or when open is set,
 * and finds pages, settings, actions and help. */
export function CommandPalette(props: {
  open: boolean;
  setOpen: (open: boolean) => void;
  pages: { id: string; label: string; about: string; group: string }[];
}) {
  const { open, setOpen } = props;
  const [q, setQ] = useState("");
  const [sel, setSel] = useState(0);
  const input = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((isMac ? e.metaKey : e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setOpen(!open);
      } else if (e.key === "/" && !open && !/^(INPUT|TEXTAREA|SELECT)$/.test((e.target as HTMLElement)?.tagName ?? "")) {
        e.preventDefault();
        setOpen(true);
      }
    };
    addEventListener("keydown", onKey);
    return () => removeEventListener("keydown", onKey);
  }, [open, setOpen]);

  useEffect(() => {
    if (open) {
      setQ("");
      setSel(0);
      setTimeout(() => input.current?.focus(), 0);
    }
  }, [open]);

  const commands: Command[] = useMemo(() => {
    const go = (id: string) => () => (location.hash = `#/${id}`);
    return [
      ...props.pages.map((p) => ({ label: p.label, hint: p.group, keywords: p.about, run: go(p.id) })),
      { label: "Add a device", hint: "Machines", keywords: "join code install connect phone laptop", run: go("machines") },
      { label: "Add a team member", hint: "Users", keywords: "admin account invite console people", run: go("users") },
      { label: "Add a user", hint: "Users", keywords: "create person owner", run: go("users") },
      { label: "Turn flow logs on or off", hint: "Settings", keywords: "flows connections monitoring", run: go("settings") },
      { label: "Turn post-quantum protection on or off", hint: "Settings", keywords: "pq ml-kem quantum", run: go("settings") },
      { label: "Set the gateway domain", hint: "Settings", keywords: "publish expose https web app", run: go("settings") },
      { label: "MagicDNS and SSH status", hint: "Settings", keywords: "dns names ssh server recording", run: go("settings") },
      { label: "Edit SSH rules", hint: "Access policy", keywords: "ssh login record", run: go("policy") },
      { label: "Create an API key", hint: "Keys", keywords: "token automation terraform mcp", run: go("keys") },
      ...helpTopics.map((t) => ({
        label: t.title,
        hint: "Help ↗",
        keywords: t.about + " " + t.group,
        run: () => window.open(doc(t.path, t.anchor), "_blank", "noopener"),
      })),
    ];
  }, [props.pages]);

  const results = useMemo(() => {
    const words = q.trim().toLowerCase().split(/\s+/).filter(Boolean);
    if (words.length === 0) return commands.slice(0, 12);
    return commands
      .map((c) => {
        const label = c.label.toLowerCase();
        const all = `${label} ${c.hint.toLowerCase()} ${(c.keywords ?? "").toLowerCase()}`;
        if (!words.every((w) => all.includes(w))) return null;
        const score = (label.startsWith(words[0]) ? 0 : label.includes(words[0]) ? 1 : 2) + (c.hint === "Help ↗" ? 0.5 : 0);
        return { c, score };
      })
      .filter((x): x is { c: Command; score: number } => x !== null)
      .sort((a, b) => a.score - b.score)
      .slice(0, 12)
      .map((x) => x.c);
  }, [q, commands]);

  if (!open) return null;
  const choose = (c?: Command) => {
    if (!c) return;
    setOpen(false);
    c.run();
  };
  return (
    <div className="palette-backdrop" onMouseDown={() => setOpen(false)}>
      <div className="palette" role="dialog" aria-label="Search" onMouseDown={(e) => e.stopPropagation()}>
        <div className="palette-input">
          <Search aria-hidden="true" className="size-4" />
          <input
            ref={input}
            autoFocus
            value={q}
            placeholder="Search pages, settings and help…"
            aria-label="Search"
            onChange={(e) => {
              setQ(e.target.value);
              setSel(0);
            }}
            onKeyDown={(e) => {
              if (e.key === "ArrowDown") {
                e.preventDefault();
                setSel((s) => Math.min(s + 1, results.length - 1));
              } else if (e.key === "ArrowUp") {
                e.preventDefault();
                setSel((s) => Math.max(s - 1, 0));
              } else if (e.key === "Enter") {
                e.preventDefault();
                choose(results[sel]);
              } else if (e.key === "Escape") {
                setOpen(false);
              }
            }}
          />
          <kbd>Esc</kbd>
        </div>
        <ul className="palette-list" role="listbox">
          {results.map((c, i) => (
            <li
              key={c.label + c.hint}
              role="option"
              aria-selected={i === sel}
              className={i === sel ? "active" : ""}
              onMouseEnter={() => setSel(i)}
              onClick={() => choose(c)}
            >
              <span>{c.label}</span>
              <span className="sub">{c.hint}</span>
            </li>
          ))}
          {results.length === 0 && <li className="empty">Nothing matches “{q}”.</li>}
        </ul>
      </div>
    </div>
  );
}
