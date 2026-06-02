import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  ReactFlow,
  Background,
  Controls,
  type Node,
  type Edge,
} from "@xyflow/react";
import { fetchDevices, type Device } from "../api";
import { useTenant } from "../TenantContext";

export default function NetworkMap() {
  const { current } = useTenant();
  const tenantId = current?.id;

  const { data: devices = [], isError } = useQuery({
    queryKey: ["devices", tenantId],
    queryFn: () => fetchDevices(tenantId!),
    enabled: !!tenantId,
    refetchInterval: 5000,
  });

  const { nodes, edges } = useMemo(() => buildGraph(devices), [devices]);

  return (
    <div className="flex h-full flex-col">
      <header className="mb-4">
        <h1 className="text-xl font-semibold">Network Map</h1>
        <p className="text-sm text-slate-500">
          Full mesh — solid links are direct (hole-punched), dashed links fall back to a relay.
        </p>
      </header>

      <div className="h-[70vh] overflow-hidden rounded-lg border border-slate-200 bg-white">
        {isError ? (
          <div className="flex h-full items-center justify-center text-slate-500">
            Couldn’t reach the coordinator (try VITE_DEMO=1).
          </div>
        ) : (
          <ReactFlow nodes={nodes} edges={edges} fitView proOptions={{ hideAttribution: true }}>
            <Background />
            <Controls />
          </ReactFlow>
        )}
      </div>
    </div>
  );
}

function buildGraph(devices: Device[]): { nodes: Node[]; edges: Edge[] } {
  const radius = 240;
  const cx = 300;
  const cy = 280;

  const nodes: Node[] = devices.map((d, i) => {
    const angle = (2 * Math.PI * i) / Math.max(devices.length, 1);
    return {
      id: d.id,
      position: { x: cx + radius * Math.cos(angle), y: cy + radius * Math.sin(angle) },
      data: { label: `${d.hostname}\n${d.overlay_ip}` },
      style: {
        borderRadius: 10,
        border: `2px solid ${d.online ? "#10b981" : "#cbd5e1"}`,
        background: "#fff",
        padding: 8,
        fontSize: 12,
        width: 150,
        whiteSpace: "pre-line",
        textAlign: "center" as const,
      },
    };
  });

  // Full mesh: connect every pair of online devices.
  const edges: Edge[] = [];
  for (let i = 0; i < devices.length; i++) {
    for (let j = i + 1; j < devices.length; j++) {
      const a = devices[i];
      const b = devices[j];
      if (!a.online || !b.online) continue;
      const relayed = a.connectivity === "relay" || b.connectivity === "relay";
      edges.push({
        id: `${a.id}-${b.id}`,
        source: a.id,
        target: b.id,
        animated: relayed,
        style: {
          stroke: relayed ? "#f59e0b" : "#10b981",
          strokeDasharray: relayed ? "6 4" : undefined,
        },
      });
    }
  }

  return { nodes, edges };
}
