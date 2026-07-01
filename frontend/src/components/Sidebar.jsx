import {
  LayoutDashboard,
  ShieldAlert,
  Brain,
  Upload,
  FileText,
  Settings,
} from "lucide-react";

import { Link } from "react-router-dom";

import Logo from "./Logo";

export default function Sidebar() {
  return (
    <aside className="w-72 bg-slate-950 border-r border-slate-800">
      <div className="p-6">
        <Logo />
      </div>

      <nav className="px-4 mt-6 space-y-2">
        <Link
          to="/"
          className="flex items-center gap-3 p-3 rounded-xl text-slate-300 hover:bg-slate-900"
        >
          <LayoutDashboard size={18} />
          Dashboard
        </Link>

        <Link
          to="/incidents"
          className="flex items-center gap-3 p-3 rounded-xl text-slate-300 hover:bg-slate-900"
        >
          <ShieldAlert size={18} />
          Incidents
        </Link>

        <Link
          to="/investigator"
          className="flex items-center gap-3 p-3 rounded-xl text-slate-300 hover:bg-slate-900"
        >
          <Brain size={18} />
          AI Investigator
        </Link>

        <Link
          to="/upload"
          className="flex items-center gap-3 p-3 rounded-xl text-slate-300 hover:bg-slate-900"
        >
          <Upload size={18} />
          Upload Logs
        </Link>

        <Link
          to="/reports"
          className="flex items-center gap-3 p-3 rounded-xl text-slate-300 hover:bg-slate-900"
        >
          <FileText size={18} />
          Reports
        </Link>

        <Link
          to="/settings"
          className="flex items-center gap-3 p-3 rounded-xl text-slate-300 hover:bg-slate-900"
        >
          <Settings size={18} />
          Settings
        </Link>
      </nav>
    </aside>
  );
}
