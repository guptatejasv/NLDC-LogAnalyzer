import MainLayout from "../layouts/MainLayout";

import KPICard from "../components/dashboard/KPICard";
import SecurityScore from "../components/dashboard/SecurityScore";
import ThreatFeed from "../components/dashboard/ThreatFeed";
import AIInsights from "../components/dashboard/AIInsights";
import IncidentChart from "../components/dashboard/IncidentChart";

import { ShieldAlert, Brain, Activity, Shield } from "lucide-react";

export default function Dashboard() {
  return (
    <MainLayout>
      <h1 className="text-white text-4xl font-bold">Security Dashboard</h1>

      <p className="text-slate-400 mt-2">
        Real-time AI security operations center
      </p>

      <div className="grid grid-cols-4 gap-5 mt-8">
        <KPICard
          title="Open Incidents"
          value="34"
          change="+12%"
          icon={<ShieldAlert className="text-red-500" />}
        />

        <KPICard
          title="Critical Threats"
          value="7"
          change="+5%"
          icon={<Activity className="text-orange-500" />}
        />

        <KPICard
          title="AI Investigations"
          value="143"
          change="+22%"
          icon={<Brain className="text-blue-500" />}
        />

        <KPICard
          title="Threats Blocked"
          value="1203"
          change="+18%"
          icon={<Shield className="text-green-500" />}
        />
      </div>

      <div className="grid grid-cols-3 gap-6 mt-8">
        <div className="col-span-2">
          <IncidentChart />
        </div>

        <SecurityScore />
      </div>

      <div className="grid grid-cols-2 gap-6 mt-8">
        <ThreatFeed />

        <AIInsights />
      </div>
    </MainLayout>
  );
}
