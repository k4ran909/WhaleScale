import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from "recharts";
import { fetchLatency, type LatencyEntry } from "../api";
import { useTenant } from "../TenantContext";

const COLORS = ["#10b981", "#3b82f6", "#f59e0b", "#ef4444", "#8b5cf6", "#ec4899"];

export default function Latency() {
  const { current } = useTenant();
  const tenantId = current?.id;

  const { data: entries = [], isError } = useQuery({
    queryKey: ["latency", tenantId],
    queryFn: () => fetchLatency(tenantId!),
    enabled: !!tenantId,
    refetchInterval: 5000,
  });

  const chartData = useMemo(() => buildChartData(entries), [entries]);

  return (
    <div>
      <header className="mb-4">
        <h1 className="text-xl font-semibold">Latency</h1>
        <p className="text-sm text-slate-500">
          STUN round-trip time per device (rolling window). Lower is better.
        </p>
      </header>

      {isError && (
        <div className="mb-4 rounded-lg border border-dashed border-slate-300 bg-white p-6 text-center text-slate-500">
          Couldn’t reach the coordinator (try VITE_DEMO=1).
        </div>
      )}

      <div className="mb-6 h-72 rounded-lg border border-slate-200 bg-white p-4">
        {chartData.length === 0 ? (
          <div className="flex h-full items-center justify-center text-slate-400">
            No latency samples yet.
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={chartData} margin={{ top: 8, right: 16, bottom: 8, left: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" />
              <XAxis dataKey="i" tick={{ fontSize: 11 }} stroke="#94a3b8" />
              <YAxis unit="ms" tick={{ fontSize: 11 }} stroke="#94a3b8" />
              <Tooltip />
              <Legend />
              {entries.map((e, idx) => (
                <Line
                  key={e.device_id}
                  type="monotone"
                  dataKey={e.hostname ?? e.device_id}
                  stroke={COLORS[idx % COLORS.length]}
                  dot={false}
                  strokeWidth={2}
                  isAnimationActive={false}
                />
              ))}
            </LineChart>
          </ResponsiveContainer>
        )}
      </div>

      <div className="overflow-hidden rounded-lg border border-slate-200 bg-white">
        <table className="w-full text-sm">
          <thead className="border-b border-slate-200 bg-slate-50 text-left text-xs uppercase tracking-wide text-slate-400">
            <tr>
              <th className="px-4 py-2 font-medium">Device</th>
              <th className="px-4 py-2 font-medium">Last</th>
              <th className="px-4 py-2 font-medium">Avg</th>
              <th className="px-4 py-2 font-medium">p95</th>
              <th className="px-4 py-2 font-medium">Tx</th>
              <th className="px-4 py-2 font-medium">Rx</th>
            </tr>
          </thead>
          <tbody>
            {entries.length === 0 && (
              <tr>
                <td colSpan={6} className="px-4 py-8 text-center text-slate-400">
                  No data.
                </td>
              </tr>
            )}
            {entries.map((e) => (
              <tr key={e.device_id} className="border-b border-slate-100 last:border-0">
                <td className="px-4 py-3 font-medium">{e.hostname ?? e.device_id}</td>
                <td className="px-4 py-3">{fmt(e.last_ms)}</td>
                <td className="px-4 py-3">{e.avg_ms != null ? `${e.avg_ms.toFixed(1)} ms` : "—"}</td>
                <td className="px-4 py-3">{fmt(e.p95_ms)}</td>
                <td className="px-4 py-3">{fmtBps(e.tx_bps)}</td>
                <td className="px-4 py-3">{fmtBps(e.rx_bps)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/** Pivot per-device sample arrays into rows keyed by sample index. */
function buildChartData(entries: LatencyEntry[]): Array<Record<string, number>> {
  const maxLen = entries.reduce((m, e) => Math.max(m, e.samples.length), 0);
  const rows: Array<Record<string, number>> = [];
  for (let i = 0; i < maxLen; i++) {
    const row: Record<string, number> = { i };
    for (const e of entries) {
      const key = e.hostname ?? e.device_id;
      // Align series to the right (most recent samples share the last index).
      const offset = maxLen - e.samples.length;
      if (i - offset >= 0) row[key] = e.samples[i - offset];
    }
    rows.push(row);
  }
  return rows;
}

function fmt(ms: number | null): string {
  return ms != null ? `${ms} ms` : "—";
}

function fmtBps(bps: number): string {
  if (!bps) return "—";
  const bits = bps * 8;
  if (bits >= 1e9) return `${(bits / 1e9).toFixed(1)} Gbps`;
  if (bits >= 1e6) return `${(bits / 1e6).toFixed(1)} Mbps`;
  if (bits >= 1e3) return `${(bits / 1e3).toFixed(0)} kbps`;
  return `${bits.toFixed(0)} bps`;
}
