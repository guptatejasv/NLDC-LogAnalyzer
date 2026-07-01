import MainLayout from "../layouts/MainLayout";

export default function AnalysisResult() {
  return (
    <MainLayout>
      <h1 className="text-4xl font-bold text-white">Investigation Result</h1>

      <div className="grid grid-cols-2 gap-6 mt-8">
        <div className="bg-slate-900 p-6 rounded-2xl">
          <h2 className="text-white text-xl">Severity</h2>

          <p className="text-red-500 text-3xl mt-3">Critical</p>
        </div>

        <div className="bg-slate-900 p-6 rounded-2xl">
          <h2 className="text-white text-xl">Confidence</h2>

          <p className="text-green-400 text-3xl mt-3">96%</p>
        </div>
      </div>

      <div className="bg-slate-900 p-6 rounded-2xl mt-6">
        <h2 className="text-white text-xl">AI Summary</h2>

        <p className="text-slate-300 mt-4">
          Sentinel AI detected a credential attack using brute-force techniques
          against privileged accounts.
        </p>
      </div>

      <div className="bg-slate-900 p-6 rounded-2xl mt-6">
        <h2 className="text-white text-xl">MITRE ATT&CK</h2>

        <div className="flex gap-3 mt-4">
          <div className="bg-slate-800 p-3 rounded-lg">T1110</div>

          <div className="bg-slate-800 p-3 rounded-lg">T1078</div>
        </div>
      </div>
    </MainLayout>
  );
}
