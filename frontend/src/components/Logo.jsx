import { Shield } from "lucide-react";

export default function Logo() {
  return (
    <div className="flex items-center gap-3">
      <Shield className="text-blue-500" size={28} />

      <div>
        <h1 className="font-bold text-xl text-white">Sentinel AI</h1>

        <p className="text-xs text-slate-400">AI Security Engineer</p>
      </div>
    </div>
  );
}
