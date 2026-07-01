import SeverityBadge from "./SeverityBadge";

const incidents = [
  {
    id: 1,
    title: "Credential Attack",
    severity: "Critical",
    status: "Open",
    confidence: 96,
  },
  {
    id: 2,
    title: "PowerShell Abuse",
    severity: "High",
    status: "Investigating",
    confidence: 88,
  },
  {
    id: 3,
    title: "Ransomware Activity",
    severity: "Critical",
    status: "Open",
    confidence: 99,
  },
];

export default function IncidentTable() {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden">
      <table className="w-full">
        <thead>
          <tr className="border-b border-slate-800">
            <th className="p-4 text-left text-slate-400">Incident</th>

            <th className="p-4 text-left text-slate-400">Severity</th>

            <th className="p-4 text-left text-slate-400">Status</th>

            <th className="p-4 text-left text-slate-400">Confidence</th>
          </tr>
        </thead>

        <tbody>
          {incidents.map((incident) => (
            <tr
              key={incident.id}
              className="border-b border-slate-800 hover:bg-slate-800"
            >
              <td className="p-4 text-white">{incident.title}</td>

              <td className="p-4">
                <SeverityBadge severity={incident.severity} />
              </td>

              <td className="p-4 text-slate-300">{incident.status}</td>

              <td className="p-4 text-slate-300">{incident.confidence}%</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
