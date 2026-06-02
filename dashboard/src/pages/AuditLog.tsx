import { useQuery } from "@tanstack/react-query";
import { fetchAudit } from "../api";
import { useTenant } from "../TenantContext";

export default function AuditLog() {
  const { current } = useTenant();
  const tenantId = current?.id;

  const { data: entries = [], isError } = useQuery({
    queryKey: ["audit", tenantId],
    queryFn: () => fetchAudit(tenantId!),
    enabled: !!tenantId,
  });

  return (
    <div>
      <h1 className="mb-6 text-xl font-semibold">Audit Log</h1>

      {isError && (
        <div className="rounded-lg border border-dashed border-slate-300 bg-white p-12 text-center text-slate-500">
          Couldn’t reach the coordinator (try VITE_DEMO=1).
        </div>
      )}

      {!isError && (
        <div className="overflow-hidden rounded-lg border border-slate-200 bg-white">
          <table className="w-full text-sm">
            <thead className="border-b border-slate-200 bg-slate-50 text-left text-xs uppercase tracking-wide text-slate-400">
              <tr>
                <th className="px-4 py-2 font-medium">Action</th>
                <th className="px-4 py-2 font-medium">Target</th>
                <th className="px-4 py-2 font-medium">When</th>
              </tr>
            </thead>
            <tbody>
              {entries.length === 0 && (
                <tr>
                  <td colSpan={3} className="px-4 py-8 text-center text-slate-400">
                    No audit entries.
                  </td>
                </tr>
              )}
              {entries.map((e, i) => (
                <tr key={i} className="border-b border-slate-100 last:border-0">
                  <td className="px-4 py-3 font-mono text-xs">{e.action}</td>
                  <td className="px-4 py-3 font-mono text-xs text-slate-500">{e.target ?? "—"}</td>
                  <td className="px-4 py-3 text-slate-500">
                    {new Date(e.created_at).toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
