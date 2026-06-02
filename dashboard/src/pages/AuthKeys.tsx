import type { ReactNode } from "react";
import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  createAuthKey,
  fetchAuthKeys,
  revokeAuthKey,
  type AuthKey,
  type CreateAuthKeyReq,
  type CreatedAuthKey,
} from "../api";
import { useTenant } from "../TenantContext";

export default function AuthKeys() {
  const { current } = useTenant();
  const qc = useQueryClient();
  const tenantId = current?.id;

  const [reusable, setReusable] = useState(false);
  const [ephemeral, setEphemeral] = useState(false);
  const [requireApproval, setRequireApproval] = useState(false);
  const [expiresInDays, setExpiresInDays] = useState<string>("");
  const [created, setCreated] = useState<CreatedAuthKey | null>(null);
  const [copied, setCopied] = useState(false);

  const { data: keys = [], isLoading, isError } = useQuery({
    queryKey: ["authkeys", tenantId],
    queryFn: () => fetchAuthKeys(tenantId!),
    enabled: !!tenantId,
  });

  const create = useMutation({
    mutationFn: (req: CreateAuthKeyReq) => createAuthKey(tenantId!, req),
    onSuccess: (res) => {
      setCreated(res);
      setCopied(false);
      qc.invalidateQueries({ queryKey: ["authkeys", tenantId] });
    },
  });

  const revoke = useMutation({
    mutationFn: (id: string) => revokeAuthKey(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["authkeys", tenantId] }),
  });

  function onGenerate() {
    const days = parseInt(expiresInDays, 10);
    create.mutate({
      reusable,
      ephemeral,
      require_approval: requireApproval,
      expires_in_days: Number.isFinite(days) && days > 0 ? days : null,
    });
  }

  async function copyKey() {
    if (!created) return;
    await navigator.clipboard.writeText(created.auth_key);
    setCopied(true);
  }

  return (
    <div>
      <header className="mb-6 flex items-center justify-between">
        <h1 className="text-xl font-semibold">Auth Keys</h1>
        <span className="text-sm text-slate-500">
          {keys.filter((k) => isActive(k)).length} active
        </span>
      </header>

      {/* One-time reveal of a freshly generated key. */}
      {created && (
        <div className="mb-6 rounded-lg border border-emerald-200 bg-emerald-50 p-4">
          <div className="mb-1 text-sm font-medium text-emerald-800">
            New auth key — copy it now, it won’t be shown again.
          </div>
          <div className="flex items-center gap-2">
            <code className="flex-1 overflow-x-auto rounded bg-white px-3 py-2 font-mono text-xs text-slate-800">
              {created.auth_key}
            </code>
            <button
              onClick={copyKey}
              className="rounded-md bg-emerald-600 px-3 py-2 text-xs font-medium text-white hover:bg-emerald-700"
            >
              {copied ? "Copied" : "Copy"}
            </button>
            <button
              onClick={() => setCreated(null)}
              className="rounded-md px-2 py-2 text-xs text-slate-500 hover:text-slate-900"
            >
              Dismiss
            </button>
          </div>
          <div className="mt-2 text-xs text-emerald-700">
            Enroll an agent with{" "}
            <code className="rounded bg-white px-1">WS_AUTH_KEY={created.auth_key.slice(0, 11)}…</code>
          </div>
        </div>
      )}

      {/* Generator. */}
      <div className="mb-6 rounded-lg border border-slate-200 bg-white p-4">
        <div className="mb-3 text-sm font-medium text-slate-700">Generate a key</div>
        <div className="flex flex-wrap items-center gap-x-6 gap-y-3">
          <Check label="Reusable" hint="Can enroll many devices" checked={reusable} onChange={setReusable} />
          <Check label="Ephemeral" hint="Devices auto-remove when offline" checked={ephemeral} onChange={setEphemeral} />
          <Check label="Require approval" hint="Admin must approve each device" checked={requireApproval} onChange={setRequireApproval} />
          <label className="flex items-center gap-2 text-sm text-slate-600">
            Expires in
            <input
              type="number"
              min={0}
              placeholder="∞"
              value={expiresInDays}
              onChange={(e) => setExpiresInDays(e.target.value)}
              className="w-20 rounded-md border border-slate-200 px-2 py-1 text-sm"
            />
            days
          </label>
          <button
            onClick={onGenerate}
            disabled={create.isPending || !tenantId}
            className="ml-auto rounded-md bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-700 disabled:opacity-50"
          >
            {create.isPending ? "Generating…" : "Generate key"}
          </button>
        </div>
        {create.isError && (
          <div className="mt-2 text-xs text-red-600">Couldn’t generate a key — is the coordinator running?</div>
        )}
      </div>

      {isLoading && <Empty>Loading keys…</Empty>}
      {isError && (
        <Empty>
          Couldn’t reach the coordinator. Start it, or run with{" "}
          <code className="rounded bg-slate-100 px-1">VITE_DEMO=1</code>.
        </Empty>
      )}
      {!isLoading && !isError && keys.length === 0 && <Empty>No auth keys yet.</Empty>}

      {keys.length > 0 && (
        <div className="overflow-hidden rounded-lg border border-slate-200 bg-white">
          <table className="w-full text-sm">
            <thead className="border-b border-slate-200 bg-slate-50 text-left text-xs uppercase tracking-wide text-slate-400">
              <tr>
                <Th>Key</Th>
                <Th>Type</Th>
                <Th>Used</Th>
                <Th>Status</Th>
                <Th>Expires</Th>
                <Th>Created</Th>
                <Th></Th>
              </tr>
            </thead>
            <tbody>
              {keys.map((k) => (
                <tr key={k.id} className="border-b border-slate-100 last:border-0">
                  <Td className="font-mono text-xs">{k.key_prefix ?? "—"}…</Td>
                  <Td>
                    <div className="flex flex-wrap gap-1">
                      {k.reusable && <Tag>reusable</Tag>}
                      {k.ephemeral && <Tag>ephemeral</Tag>}
                      {k.require_approval && <Tag>approval</Tag>}
                      {!k.reusable && !k.ephemeral && !k.require_approval && (
                        <span className="text-xs text-slate-400">single-use</span>
                      )}
                    </div>
                  </Td>
                  <Td className="text-slate-500">{k.used_count}</Td>
                  <Td><StatusPill k={k} /></Td>
                  <Td className="text-slate-500">{k.expires_at ? relativeTime(k.expires_at) : "never"}</Td>
                  <Td className="text-slate-500">{relativeTime(k.created_at)}</Td>
                  <Td>
                    <div className="flex justify-end">
                      {!k.revoked && (
                        <button
                          onClick={() => revoke.mutate(k.id)}
                          className="text-xs font-medium text-red-600 hover:underline"
                        >
                          Revoke
                        </button>
                      )}
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

function isActive(k: AuthKey): boolean {
  if (k.revoked) return false;
  if (k.expires_at && new Date(k.expires_at).getTime() < Date.now()) return false;
  return true;
}

function StatusPill({ k }: { k: AuthKey }) {
  const expired = !!k.expires_at && new Date(k.expires_at).getTime() < Date.now();
  const [label, color] = k.revoked
    ? ["revoked", "bg-red-100 text-red-700"]
    : expired
      ? ["expired", "bg-slate-100 text-slate-500"]
      : ["active", "bg-emerald-100 text-emerald-700"];
  return <span className={"rounded-full px-2 py-0.5 text-xs font-medium " + color}>{label}</span>;
}

function Check({
  label,
  hint,
  checked,
  onChange,
}: {
  label: string;
  hint: string;
  checked: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <label className="flex items-center gap-2 text-sm text-slate-600" title={hint}>
      <input type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)} />
      {label}
    </label>
  );
}

function Tag({ children }: { children: ReactNode }) {
  return (
    <span className="rounded bg-slate-100 px-1.5 py-0.5 text-xs font-medium text-slate-600">
      {children}
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

function relativeTime(iso: string): string {
  const diff = new Date(iso).getTime() - Date.now();
  const past = diff < 0;
  const secs = Math.floor(Math.abs(diff) / 1000);
  const fmt =
    secs < 60
      ? `${secs}s`
      : secs < 3600
        ? `${Math.floor(secs / 60)}m`
        : secs < 86400
          ? `${Math.floor(secs / 3600)}h`
          : `${Math.floor(secs / 86400)}d`;
  return past ? `${fmt} ago` : `in ${fmt}`;
}
