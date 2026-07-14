import { Bell, Search, UserCircle } from "lucide-react";

export default function Navbar() {
  return (
    <div className="h-20 border-b border-slate-800 flex items-center justify-between px-8">
      <div className="relative flex items-center">
        <img
          src="/logo/logo.png"
          alt="NLDC Grid India"
          className="h-10 w-auto object-contain"
        />
      </div>

      <div className="flex items-center gap-6">
        <Bell className="text-slate-400 cursor-pointer" size={22} />
        <UserCircle className="text-slate-400 cursor-pointer" size={34} />
      </div>
    </div>
  );
}
