import type { ReactNode } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { approveDevice, deleteDevice, fetchDevices, type Device } from "../api";
import { useTenant } from "../TenantContext";

export default function Devices() {
  const { current } = useTenant();
  const qc = useQueryClient();
  const tenantId = current?.id;

  const { data: devices = [], isLoading, isError } = useQuery({
    queryKey: ["devices", tenantId],
    queryFn: () => fetchDevices(tenantId!),
    enabled: !!tenantId,
    refetchInterval: 5000,
  });

  const remove = useMutation({
    mutationFn: (id: string) => deleteDevice(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["devices", tenantId] }),
  });

  const approve = useMutation({
    mutationFn: (id: string) => approveDevice(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["devices", tenantId] }),
  });

  const pending = devices.filter((d) => !d.approved).length;

  return (
    <div>
      <header className="mb-6 flex items-center justify-between">
        <h1 className="text-xl font-semibold">Devices</h1>
        <div className="flex items-center gap-3 text-sm text-slate-500">
          {pending > 0 && (
            <span className="rounded-full bg-amber-100 px-2 py-0.5 text-xs font-medium text-amber-700">
              {pending} pending approval
            </span>
          )}
          <span>
            {devices.filter((d) => d.online).length} / {devices.length} online
          </span>
        </div>
      </header>

      {isLoading && <Empty>Loading devices…</Empty>}
      {isError && (
        <Empty>
          Couldn’t reach the coordinator. Start it, or run the dashboard with{" "}
          <code className="rounded bg-slate-100 px-1">VITE_DEMO=1</code>.
        </Empty>
      )}
      {!isLoading && !isError && devices.length === 0 && (
        <Empty>No devices enrolled yet.</Empty>
      )}

      {devices.length > 0 && (
        <div className="overflow-hidden rounded-lg border border-slate-200 bg-white">
          <table className="w-full text-sm">
            <thead className="border-b border-slate-200 bg-slate-50 text-left text-xs uppercase tracking-wide text-slate-400">
              <tr>
                <Th>Status</Th>
                <Th>Hostname</Th>
                <Th>OS</Th>
                <Th>Overlay IP</Th>
                <Th>Connectivity</Th>
                <Th>Last seen</Th>
                <Th></Th>
              </tr>
            </thead>
            <tbody>
              {devices.map((d) => (
                <tr key={d.id} className="border-b border-slate-100 last:border-0">
                  <Td>
                    {d.approved ? (
                      <StatusDot online={d.online} />
                    ) : (
                      <span className="rounded-full bg-amber-100 px-2 py-0.5 text-xs font-medium text-amber-700">
                        pending
                      </span>
                    )}
                  </Td>
                  <Td className="font-medium">{d.hostname}</Td>
                  <Td className="text-slate-500">{d.os}</Td>
                  <Td className="font-mono text-xs">{d.overlay_ip}</Td>
                  <Td><ConnPill device={d} /></Td>
                  <Td className="text-slate-500">{relativeTime(d.last_seen)}</Td>
                  <Td>
                    <div className="flex justify-end gap-3">
                      {!d.approved && (
                        <button
                          onClick={() => approve.mutate(d.id)}
                          className="text-xs font-medium text-emerald-600 hover:underline"
                        >
                          Approve
                        </button>
                      )}
                      <button
                        onClick={() => remove.mutate(d.id)}
                        className="text-xs font-medium text-red-600 hover:underline"
                      >
                        Remove
                      </button>
                    </div>
                  </Td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function ConnPill({ device }: { device: Device }) {
  const direct = device.connectivity === "direct";
  return (
    <span
      className={
        "rounded-full px-2 py-0.5 text-xs font-medium " +
        (direct ? "bg-emerald-100 text-emerald-700" : "bg-amber-100 text-amber-700")
      }
      title={direct ? `${device.endpoint_count} endpoint(s)` : `via ${device.relay_region ?? "relay"}`}
    >
      {direct ? "direct" : "relayed"}
    </span>
  );
}

function StatusDot({ online }: { online: boolean }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className={"h-2 w-2 rounded-full " + (online ? "bg-emerald-500" : "bg-slate-300")} />
      <span className="text-xs text-slate-500">{online ? "online" : "offline"}</span>
    </span>
  );
}

function Th({ children }: { children?: ReactNode }) {
  return <th className="px-4 py-2 font-medium">{children}</th>;
}
function Td({ children, className = "" }: { children?: ReactNode; className?: string }) {
  return <td className={"px-4 py-3 " + className}>{children}</td>;
}
function Empty({ children }: { children: ReactNode }) {
  return (
    <div className="rounded-lg border border-dashed border-slate-300 bg-white p-12 text-center text-slate-500">
      {children}
    </div>
  );
}

function relativeTime(iso: string | null): string {
  if (!iso) return "never";
  const secs = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (secs < 60) return `${secs}s ago`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
  return `${Math.floor(secs / 86400)}d ago`;
}
