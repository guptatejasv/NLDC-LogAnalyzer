import { Bell, Search, UserCircle } from "lucide-react";

export default function Navbar() {
  return (
    <div className="h-20 border-b border-slate-800 flex items-center justify-between px-8">
      <div className="relative">
        <Search className="absolute left-3 top-3 text-slate-500" size={18} />

        <input
          placeholder="Search incidents..."
          className="bg-slate-900 border border-slate-700 rounded-lg pl-10 pr-4 py-2 w-96 text-white outline-none"
        />
      </div>

      <div className="flex items-center gap-6">
        <Bell className="text-slate-400 cursor-pointer" size={22} />

        <UserCircle className="text-slate-400 cursor-pointer" size={34} />
      </div>
    </div>
  );
}
