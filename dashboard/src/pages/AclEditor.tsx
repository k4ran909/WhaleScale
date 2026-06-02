import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { fetchAcl, saveAcl } from "../api";
import { useTenant } from "../TenantContext";

export default function AclEditor() {
  const { current } = useTenant();
  const tenantId = current?.id;

  const { data, isSuccess } = useQuery({
    queryKey: ["acl", tenantId],
    queryFn: () => fetchAcl(tenantId!),
    enabled: !!tenantId,
  });

  const [text, setText] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (isSuccess) setText(JSON.stringify(data, null, 2));
  }, [isSuccess, data]);

  function validateLocal(): unknown | null {
    try {
      const parsed = JSON.parse(text);
      setError(null);
      return parsed;
    } catch (e) {
      setError(`JSON syntax error: ${(e as Error).message}`);
      return null;
    }
  }

  async function onSave() {
    const parsed = validateLocal();
    if (parsed === null) return;
    setSaving(true);
    setSaved(false);
    const serverError = await saveAcl(tenantId!, parsed);
    setSaving(false);
    if (serverError) {
      setError(serverError);
    } else {
      setError(null);
      setSaved(true);
    }
  }

  return (
    <div>
      <header className="mb-4">
        <h1 className="text-xl font-semibold">ACL Policy</h1>
        <p className="text-sm text-slate-500">
          Tailscale-style allow rules. Selectors: <code>*</code>, <code>group:NAME</code>,{" "}
          <code>tag:NAME</code>, or a user email. A peer is visible to a node only when a
          rule permits traffic in either direction.
        </p>
      </header>

      <textarea
        value={text}
        onChange={(e) => {
          setText(e.target.value);
          setSaved(false);
        }}
        spellCheck={false}
        className="h-[55vh] w-full rounded-lg border border-slate-200 bg-white p-4 font-mono text-xs"
      />

      <div className="mt-3 flex items-center gap-3">
        <button
          onClick={() => validateLocal() !== null && setError(null)}
          className="rounded-md border border-slate-300 px-3 py-1.5 text-sm font-medium hover:bg-slate-50"
        >
          Validate
        </button>
        <button
          onClick={onSave}
          disabled={saving}
          className="rounded-md bg-slate-900 px-3 py-1.5 text-sm font-medium text-white hover:bg-slate-700 disabled:opacity-50"
        >
          {saving ? "Saving…" : "Save policy"}
        </button>
        {error && <span className="text-sm text-red-600">{error}</span>}
        {saved && !error && <span className="text-sm text-emerald-600">Saved ✓</span>}
      </div>
    </div>
  );
}
