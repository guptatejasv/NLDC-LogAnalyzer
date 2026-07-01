export default function IncidentFilters() {
  return (
    <div className="flex gap-4">
      <select className="bg-slate-900 border border-slate-700 rounded-lg px-4 py-2 text-white">
        <option>All Severity</option>
        <option>Critical</option>
        <option>High</option>
        <option>Medium</option>
        <option>Low</option>
      </select>

      <select className="bg-slate-900 border border-slate-700 rounded-lg px-4 py-2 text-white">
        <option>All Status</option>
        <option>Open</option>
        <option>Investigating</option>
        <option>Resolved</option>
      </select>
    </div>
  );
}
