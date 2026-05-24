"use client";
import { useEffect } from "react";
export function TelemetryProvider({ children }: { children: React.ReactNode }) {
  useEffect(() => {
    // In production: initialize OpenTelemetry browser SDK
    console.log("[APEX] Telemetry initialized");
  }, []);
  return <>{children}</>;
}
