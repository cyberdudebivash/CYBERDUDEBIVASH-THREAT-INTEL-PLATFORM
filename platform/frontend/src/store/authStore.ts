import { create } from "zustand";

interface AuthState {
  user: { id: string; email: string; name: string } | null;
  tier: string;
  token: string | null;
  setUser: (user: AuthState["user"], tier: string, token: string) => void;
  logout: () => void;
}

export const useAuthStore = create<AuthState>((set) => ({
  user: { id: "cdb-001", email: "bivashnayak.ai007@gmail.com", name: "CYBERDUDEBIVASH" },
  tier: "enterprise",
  token: null,
  setUser: (user, tier, token) => set({ user, tier, token }),
  logout: () => set({ user: null, tier: "free", token: null }),
}));
