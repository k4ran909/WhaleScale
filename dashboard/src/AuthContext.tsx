import { createContext, useContext, useState, type ReactNode } from "react";
import { clearToken, getToken, DEMO, type Session } from "./api";

type AuthCtx = {
  signedIn: boolean;
  role: Session["role"] | null;
  email: string | null;
  onSignIn: (session: Session) => void;
  signOut: () => void;
};

const Ctx = createContext<AuthCtx | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setTok] = useState<string | null>(() => getToken());
  const [role, setRole] = useState<Session["role"] | null>(null);
  const [email, setEmail] = useState<string | null>(null);

  const onSignIn = (s: Session) => {
    setTok(s.token);
    setRole(s.role);
    setEmail(s.email);
  };

  const signOut = () => {
    clearToken();
    setTok(null);
    setRole(null);
    setEmail(null);
  };

  return (
    <Ctx.Provider value={{ signedIn: DEMO || !!token, role, email, onSignIn, signOut }}>
      {children}
    </Ctx.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
