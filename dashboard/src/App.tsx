import { NavLink, Outlet } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { useTenant } from "./TenantContext";
import { useAuth } from "./AuthContext";

const NAV = [
  { to: "/devices", label: "Devices" },
  { to: "/network", label: "Network Map" },
  { to: "/authkeys", label: "Auth Keys" },
  { to: "/latency", label: "Latency" },
  { to: "/acl", label: "ACL Policy" },
  { to: "/team", label: "Team" },
  { to: "/audit", label: "Audit Log" },
];

function useHealth() {
  return useQuery<{ status: string }>({
    queryKey: ["health"],
    queryFn: async () => {
      const res = await fetch("/api/healthz");
      if (!res.ok) throw new Error("unhealthy");
      return res.json();
    },
    refetchInterval: 5000,
    retry: false,
  });
}

export default function App() {
  const health = useHealth();

  return (
    <div className="flex min-h-screen bg-slate-50 text-slate-900">
      <aside className="flex w-60 shrink-0 flex-col border-r border-slate-200 bg-white p-4">
        <div className="mb-6 flex items-center gap-2">
          <span className="text-2xl">🐋</span>
          <span className="text-lg font-semibold">WhaleScale</span>
        </div>

        <OrgSwitcher />

        <nav className="mt-6 space-y-1">
          {NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                "block rounded-md px-3 py-2 text-sm font-medium " +
                (isActive
                  ? "bg-slate-100 text-slate-900"
                  : "text-slate-500 hover:bg-slate-50")
              }
            >
              {item.label}
            </NavLink>
          ))}
        </nav>

        <div className="mt-auto space-y-3 pt-4">
          <UserCard />
          <HealthPill ok={health.isSuccess} loading={health.isLoading} />
        </div>
      </aside>

      <main className="flex-1 p-8">
        <Outlet />
      </main>
    </div>
  );
}

function OrgSwitcher() {
  const { tenants, current, setCurrentId } = useTenant();
  return (
    <div>
      <label className="mb-1 block text-xs font-medium uppercase tracking-wide text-slate-400">
        Organization
      </label>
      <select
        className="w-full rounded-md border border-slate-200 bg-white px-2 py-1.5 text-sm"
        value={current?.id ?? ""}
        onChange={(e) => setCurrentId(e.target.value)}
      >
        {tenants.length === 0 && <option value="">No organizations</option>}
        {tenants.map((t) => (
          <option key={t.id} value={t.id}>
            {t.name} ({t.device_count})
          </option>
        ))}
      </select>
    </div>
  );
}

function UserCard() {
  const { email, role, signOut } = useAuth();
  if (!email) return null;
  return (
    <div className="rounded-md border border-slate-200 p-2 text-xs">
      <div className="truncate font-medium text-slate-700">{email}</div>
      <div className="mb-1 text-slate-400">{role}</div>
      <button onClick={signOut} className="text-slate-500 hover:text-slate-900">
        Sign out
      </button>
    </div>
  );
}

function HealthPill({ ok, loading }: { ok: boolean; loading: boolean }) {
  const label = loading ? "checking…" : ok ? "coordinator online" : "coordinator offline";
  const color = loading
    ? "bg-slate-100 text-slate-500"
    : ok
      ? "bg-emerald-100 text-emerald-700"
      : "bg-red-100 text-red-700";
  return (
    <span className={"inline-block rounded-full px-3 py-1 text-xs font-medium " + color}>
      {label}
    </span>
  );
}
