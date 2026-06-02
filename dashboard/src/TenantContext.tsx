import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { fetchTenants, type Tenant } from "./api";

type TenantCtx = {
  tenants: Tenant[];
  current: Tenant | null;
  setCurrentId: (id: string) => void;
  loading: boolean;
};

const Ctx = createContext<TenantCtx | null>(null);

export function TenantProvider({ children }: { children: ReactNode }) {
  const { data: tenants = [], isLoading } = useQuery({
    queryKey: ["tenants"],
    queryFn: fetchTenants,
  });
  const [currentId, setCurrentId] = useState<string | null>(
    () => localStorage.getItem("ws.tenant")
  );

  // Default to the first tenant once loaded.
  useEffect(() => {
    if (!currentId && tenants.length > 0) setCurrentId(tenants[0].id);
  }, [tenants, currentId]);

  useEffect(() => {
    if (currentId) localStorage.setItem("ws.tenant", currentId);
  }, [currentId]);

  const current = tenants.find((t) => t.id === currentId) ?? null;

  return (
    <Ctx.Provider value={{ tenants, current, setCurrentId, loading: isLoading }}>
      {children}
    </Ctx.Provider>
  );
}

export function useTenant() {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useTenant must be used within TenantProvider");
  return ctx;
}
