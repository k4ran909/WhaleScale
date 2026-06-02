import React from "react";
import ReactDOM from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createBrowserRouter, RouterProvider, Navigate } from "react-router-dom";
import App from "./App";
import Devices from "./pages/Devices";
import NetworkMap from "./pages/NetworkMap";
import AclEditor from "./pages/AclEditor";
import Latency from "./pages/Latency";
import AuditLog from "./pages/AuditLog";
import Login from "./pages/Login";
import { TenantProvider } from "./TenantContext";
import { AuthProvider, useAuth } from "./AuthContext";
import "@xyflow/react/dist/style.css";
import "./index.css";

const queryClient = new QueryClient();

const router = createBrowserRouter([
  {
    path: "/",
    element: <App />,
    children: [
      { index: true, element: <Navigate to="/devices" replace /> },
      { path: "devices", element: <Devices /> },
      { path: "network", element: <NetworkMap /> },
      { path: "latency", element: <Latency /> },
      { path: "acl", element: <AclEditor /> },
      { path: "audit", element: <AuditLog /> },
    ],
  },
]);

/** Render the app when signed in (or in demo mode), otherwise the login form. */
function Gate() {
  const { signedIn } = useAuth();
  if (!signedIn) return <Login />;
  return (
    <TenantProvider>
      <RouterProvider router={router} />
    </TenantProvider>
  );
}

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <Gate />
      </AuthProvider>
    </QueryClientProvider>
  </React.StrictMode>
);
