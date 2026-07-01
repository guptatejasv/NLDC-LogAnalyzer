export default function EvidencePanel() {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
      <h3 className="text-white text-xl font-semibold">Evidence</h3>

      <div className="space-y-4 mt-5">
        <div className="bg-slate-800 p-4 rounded-xl">
          <p className="text-slate-300">Source IP</p>

          <p className="text-white">185.45.11.82</p>
        </div>

        <div className="bg-slate-800 p-4 rounded-xl">
          <p className="text-slate-300">Username</p>

          <p className="text-white">Administrator</p>
        </div>

        <div className="bg-slate-800 p-4 rounded-xl">
          <p className="text-slate-300">Event IDs</p>

          <p className="text-white">4625, 4624</p>
        </div>
      </div>
    </div>
  );
}
