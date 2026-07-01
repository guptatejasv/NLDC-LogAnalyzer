import MainLayout from "../layouts/MainLayout";
import SeverityBadge from "../components/incidents/SeverityBadge";

export default function IncidentDetails() {
  return (
    <MainLayout>
      <div className="flex items-center gap-4">
        <h1 className="text-4xl text-white font-bold">Credential Attack</h1>

        <SeverityBadge severity="Critical" />
      </div>

      <p className="text-slate-400 mt-3">Confidence Score: 96%</p>

      <div className="grid grid-cols-2 gap-6 mt-8">
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
          <h2 className="text-xl font-semibold text-white">
            AI Investigation Summary
          </h2>

          <p className="text-slate-300 mt-4">
            Sentinel AI identified a brute-force attack targeting privileged
            accounts.
          </p>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
          <h2 className="text-xl font-semibold text-white">MITRE ATT&CK</h2>

          <div className="space-y-3 mt-4">
            <div className="bg-slate-800 p-3 rounded-lg text-white">
              T1110 - Brute Force
            </div>

            <div className="bg-slate-800 p-3 rounded-lg text-white">
              T1078 - Valid Accounts
            </div>
          </div>
        </div>
      </div>
    </MainLayout>
  );
}
