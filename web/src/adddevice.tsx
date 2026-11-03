import { useEffect, useRef, useState } from "react";
import { api, Node } from "./api";
import { Banner, CopyField, errText, useLoad } from "./ui";

const releases = "https://github.com/k4ran909/WhaleScale/releases/latest/download";
const installScript = "https://raw.githubusercontent.com/k4ran909/WhaleScale/main/deploy/install.sh";

type OS = "windows" | "linux" | "macos";

function guessOS(): OS {
  const p = navigator.userAgent;
  if (/Windows/i.test(p)) return "windows";
  if (/Mac/i.test(p)) return "macos";
  return "linux";
}

/** AddDevice walks through adding a machine: a join code, the steps for
 * the device's system, and a live check until the machine shows up. */
export function AddDevice({ onClose }: { onClose: () => void }) {
  const { data: users, reload: reloadUsers } = useLoad(api.listUsers);
  const { data: me } = useLoad(api.whoAmI);
  const [user, setUser] = useState("");
  const [newUser, setNewUser] = useState("");
  const [several, setSeveral] = useState(false);
  const [code, setCode] = useState<string>();
  const [os, setOS] = useState<OS>(guessOS);
  const [err, setErr] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [joined, setJoined] = useState<Node[]>([]);
  const known = useRef<Set<string>>();

  // Default owner: the signed-in admin's own user, else the first one.
  useEffect(() => {
    if (user || !users?.length) return;
    setUser(users.some((u) => u.name === me?.identity) ? me!.identity : users[0].name);
  }, [users, me, user]);

  // Once there's a code, watch for machines that weren't there before.
  useEffect(() => {
    if (!code) return;
    let stop = false;
    const tick = async () => {
      try {
        const nodes = await api.listNodes();
        if (!known.current) known.current = new Set(nodes.map((n) => n.id));
        else setJoined(nodes.filter((n) => !known.current!.has(n.id)));
      } catch {
        /* keep polling */
      }
      if (!stop) setTimeout(tick, 3000);
    };
    tick();
    return () => {
      stop = true;
    };
  }, [code]);

  const create = async () => {
    setBusy(true);
    setErr(undefined);
    try {
      let owner = user;
      if (!users?.length) {
        owner = newUser.trim().toLowerCase();
        await api.createUser(owner);
        reloadUsers();
      }
      known.current = undefined;
      const r = await api.createPreAuthKey(owner, several, false, several ? 7 * 86400 : 86400);
      setCode(r.joinCode || r.secret);
      setJoined([]);
    } catch (e) {
      setErr(errText(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="secret" role="dialog" aria-label="Add a device">
      <div className="secret-head">
        <strong>Add a device</strong>
        <button className="btn ghost" onClick={onClose}>Close</button>
      </div>
      {err && <Banner kind="error">{err}</Banner>}

      {!code ? (
        <form
          className="form-grid"
          onSubmit={(e) => {
            e.preventDefault();
            create();
          }}
        >
          {users && users.length > 0 ? (
            <label>
              Belongs to
              <select value={user} onChange={(e) => setUser(e.target.value)}>
                {users.map((u) => (
                  <option key={u.id}>{u.name}</option>
                ))}
              </select>
            </label>
          ) : (
            <label>
              Owner (a new user)
              <input value={newUser} onChange={(e) => setNewUser(e.target.value)} placeholder="karan" pattern="[a-zA-Z0-9][a-zA-Z0-9-]*" required />
            </label>
          )}
          <label>
            For
            <select value={several ? "several" : "one"} onChange={(e) => setSeveral(e.target.value === "several")}>
              <option value="one">One device (code works once, for a day)</option>
              <option value="several">Several devices (for 7 days)</option>
            </select>
          </label>
          <button className="btn primary" disabled={busy || !users}>
            {busy ? "Creating…" : "Get a join code"}
          </button>
        </form>
      ) : (
        <>
          <p className="muted">
            Join code{several ? " (works for several devices for 7 days)" : " (works once, for a day)"}. It's a password
            for your network: only paste it on your own devices.
          </p>
          <CopyField text={code} />

          <div className="tabs" role="tablist">
            {(["windows", "macos", "linux"] as OS[]).map((o) => (
              <button key={o} type="button" role="tab" aria-selected={os === o} className={os === o ? "tab active" : "tab"} onClick={() => setOS(o)}>
                {{ windows: "Windows", macos: "macOS", linux: "Linux" }[o]}
              </button>
            ))}
          </div>
          {os === "windows" ? (
            <ol className="steps">
              <li>
                <a className="btn primary" href={`${releases}/whalescale-setup-windows-amd64.exe`}>Download the installer</a>{" "}
                <span className="sub">
                  (for ARM laptops: <a href={`${releases}/whalescale-setup-windows-arm64.exe`}>the ARM version</a>)
                </span>
              </li>
              <li>
                Run it. If Windows says it protected your PC, click <strong>More info → Run anyway</strong> (the installer
                isn't code-signed yet).
              </li>
              <li>Paste the join code when the installer asks for it, and click Install.</li>
            </ol>
          ) : (
            <ol className="steps">
              <li>
                Open a terminal on the {os === "macos" ? "Mac" : "machine"} and run:
                <CopyField text={`curl -fsSL ${installScript} | sh -s -- --join ${code}`} />
              </li>
              <li>It installs Whalescale, starts it, and joins your network.</li>
            </ol>
          )}
          <p className="sub">
            Whalescale already installed? Run this instead{os === "windows" ? " in a terminal opened as Administrator" : ""}:
          </p>
          <CopyField text={`${os === "windows" ? "ws" : "sudo ws"} login ${code}`} />

          {joined.length > 0 ? (
            <Banner kind="ok">
              {joined.map((n) => (
                <div key={n.id}>
                  ✓ <strong>{n.name}</strong> joined{n.addresses?.length ? ` as ${n.addresses[0]}` : ""}.
                </div>
              ))}
            </Banner>
          ) : (
            <p className="waiting">
              <span className="pulse" aria-hidden="true" /> Waiting for the device to join…
            </p>
          )}
          <div className="row">
            <button className="btn" onClick={() => setCode(undefined)}>Another code</button>
            <button className="btn ghost" onClick={onClose}>Done</button>
          </div>
        </>
      )}
    </div>
  );
}
