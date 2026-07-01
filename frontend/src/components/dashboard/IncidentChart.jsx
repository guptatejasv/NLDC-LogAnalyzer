import { ResponsiveContainer, AreaChart, Area, XAxis, Tooltip } from "recharts";

const data = [
  { month: "Jan", incidents: 15 },
  { month: "Feb", incidents: 28 },
  { month: "Mar", incidents: 44 },
  { month: "Apr", incidents: 36 },
  { month: "May", incidents: 52 },
];

export default function IncidentChart() {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
      <h3 className="text-white text-xl font-semibold mb-4">Incident Trend</h3>

      <ResponsiveContainer width="100%" height={300}>
        <AreaChart data={data}>
          <XAxis dataKey="month" />
          <Tooltip />
          <Area type="monotone" dataKey="incidents" />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
