export default function AIInsights() {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
      <h3 className="text-white text-xl font-semibold mb-5">AI Insights</h3>

      <div className="space-y-4">
        <div className="bg-slate-800 p-4 rounded-xl">
          <p className="text-white">3 incidents are linked to the same IP.</p>
        </div>

        <div className="bg-slate-800 p-4 rounded-xl">
          <p className="text-white">Brute-force activity increased by 42%.</p>
        </div>

        <div className="bg-slate-800 p-4 rounded-xl">
          <p className="text-white">One admin account lacks MFA.</p>
        </div>
      </div>
    </div>
  );
}
