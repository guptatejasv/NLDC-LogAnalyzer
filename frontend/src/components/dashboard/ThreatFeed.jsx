const alerts = [
  {
    time: "08:21",
    title: "Credential Attack",
    severity: "Critical",
  },
  {
    time: "08:32",
    title: "PowerShell Abuse",
    severity: "High",
  },
  {
    time: "08:44",
    title: "Ransomware Activity",
    severity: "Critical",
  },
];

export default function ThreatFeed() {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
      <h3 className="text-white text-xl font-semibold mb-6">
        Live Threat Feed
      </h3>

      <div className="space-y-4">
        {alerts.map((alert, index) => (
          <div key={index} className="border-b border-slate-800 pb-4">
            <div className="flex justify-between">
              <span className="text-white">{alert.title}</span>

              <span className="text-red-400">{alert.severity}</span>
            </div>

            <p className="text-slate-500 text-sm mt-1">{alert.time}</p>
          </div>
        ))}
      </div>
    </div>
  );
}
