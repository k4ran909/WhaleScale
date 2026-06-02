import type { ReactNode } from "react";
import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  createUser,
  deleteUser,
  fetchUsers,
  updateUserRole,
  type Role,
} from "../api";
import { useTenant } from "../TenantContext";
import { useAuth } from "../AuthContext";

const ROLES: Role[] = ["member", "admin", "owner"];
const RANK: Record<Role, number> = { owner: 3, admin: 2, member: 1 };

/** Client-side mirror of the server's RBAC (UX only; server is authoritative). */
function canChangeRole(actor: Role, current: Role, next: Role): boolean {
  if (RANK[actor] < RANK.admin) return false;
  if (current === "owner" && actor !== "owner") return false;
  if (next === "owner" && actor !== "owner") return false;
  return true;
}
function canDelete(actor: Role, target: Role): boolean {
  return RANK[actor] >= RANK.admin && (target !== "owner" || actor === "owner");
}
/** Roles `actor` is allowed to assign when inviting/changing. */
function assignableRoles(actor: Role): Role[] {
  return ROLES.filter((r) => (r === "owner" ? actor === "owner" : RANK[actor] >= RANK.admin));
}

export default function Team() {
  const { current } = useTenant();
  const { role, email: myEmail } = useAuth();
  const qc = useQueryClient();
  const tenantId = current?.id;
  // In demo mode there's no live session role; assume owner so the UI is explorable.
  const myRole: Role = role ?? "owner";
  const canManage = RANK[myRole] >= RANK.admin;

  const { data: users = [], isLoading, isError } = useQuery({
    queryKey: ["users", tenantId],
    queryFn: () => fetchUsers(tenantId!),
    enabled: !!tenantId,
  });

  const invite = useMutation({
    mutationFn: (b: { email: string; password: string; role: Role }) => createUser(tenantId!, b),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["users", tenantId] });
      setEmail("");
      setPassword("");
    },
  });
  const changeRole = useMutation({
    mutationFn: ({ id, role }: { id: string; role: Role }) => updateUserRole(id, role),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["users", tenantId] }),
  });
  const remove = useMutation({
    mutationFn: (id: string) => deleteUser(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["users", tenantId] }),
  });

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [inviteRole, setInviteRole] = useState<Role>("member");

  const actionError =
    (invite.error as Error | null)?.message ??
    (changeRole.error as Error | null)?.message ??
    (remove.error as Error | null)?.message ??
    null;

  return (
    <div>
      <header className="mb-6 flex items-center justify-between">
        <h1 className="text-xl font-semibold">Team</h1>
        <span className="text-sm text-slate-500">{users.length} member(s)</span>
      </header>

      {actionError && (
        <div className="mb-4 rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
          {actionError}
        </div>
      )}

      {canManage && (
        <div className="mb-6 rounded-lg border border-slate-200 bg-white p-4">
          <div className="mb-3 text-sm font-medium text-slate-700">Invite a user</div>
          <div className="flex flex-wrap items-center gap-3">
            <input
              type="email"
              placeholder="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="flex-1 rounded-md border border-slate-200 px-3 py-2 text-sm"
            />
            <input
              type="password"
              placeholder="temporary password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="flex-1 rounded-md border border-slate-200 px-3 py-2 text-sm"
            />
            <select
              value={inviteRole}
              onChange={(e) => setInviteRole(e.target.value as Role)}
              className="rounded-md border border-slate-200 px-2 py-2 text-sm capitalize"
            >
              {assignableRoles(myRole).map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </select>
            <button
              onClick={() => invite.mutate({ email, password, role: inviteRole })}
              disabled={invite.isPending || !email || !password || !tenantId}
              className="rounded-md bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-700 disabled:opacity-50"
            >
              {invite.isPending ? "Adding…" : "Add user"}
            </button>
          </div>
        </div>
      )}

      {isLoading && <Empty>Loading team…</Empty>}
      {isError && (
        <Empty>
          Couldn’t reach the coordinator. Start it, or run with{" "}
          <code className="rounded bg-slate-100 px-1">VITE_DEMO=1</code>.
        </Empty>
      )}
      {!isLoading && !isError && users.length === 0 && <Empty>No users yet.</Empty>}

      {users.length > 0 && (
        <div className="overflow-hidden rounded-lg border border-slate-200 bg-white">
          <table className="w-full text-sm">
            <thead className="border-b border-slate-200 bg-slate-50 text-left text-xs uppercase tracking-wide text-slate-400">
              <tr>
                <Th>Email</Th>
                <Th>Role</Th>
                <Th>Joined</Th>
                <Th></Th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.id} className="border-b border-slate-100 last:border-0">
                  <Td className="font-medium">
                    {u.email}
                    {myEmail && u.email === myEmail && (
                      <span className="ml-2 rounded bg-slate-100 px-1.5 py-0.5 text-xs text-slate-500">
                        you
                      </span>
                    )}
                  </Td>
                  <Td>
                    {canChangeRole(myRole, u.role, "member") || canChangeRole(myRole, u.role, "admin") ? (
                      <RoleSelect
                        value={u.role}
                        options={roleOptionsFor(myRole, u.role)}
                        onChange={(role) => changeRole.mutate({ id: u.id, role })}
                      />
                    ) : (
                      <span className="capitalize text-slate-600">{u.role}</span>
                    )}
                  </Td>
                  <Td className="text-slate-500">{relativeTime(u.created_at)}</Td>
                  <Td>
                    <div className="flex justify-end">
                      {canDelete(myRole, u.role) && (
                        <button
                          onClick={() => remove.mutate(u.id)}
                          className="text-xs font-medium text-red-600 hover:underline"
                        >
                          Remove
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

/** The role options to offer for a given target row: those the actor can assign,
 *  plus the current role (so it shows as selected even if not re-assignable). */
function roleOptionsFor(actor: Role, current: Role): Role[] {
  const opts = new Set<Role>(assignableRoles(actor).filter((r) => canChangeRole(actor, current, r)));
  opts.add(current);
  return ROLES.filter((r) => opts.has(r));
}

function RoleSelect({
  value,
  options,
  onChange,
}: {
  value: Role;
  options: Role[];
  onChange: (r: Role) => void;
}) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value as Role)}
      className="rounded-md border border-slate-200 px-2 py-1 text-sm capitalize"
    >
      {options.map((r) => (
        <option key={r} value={r}>
          {r}
        </option>
      ))}
    </select>
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
  const secs = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (secs < 60) return `${secs}s ago`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
  return `${Math.floor(secs / 86400)}d ago`;
}
