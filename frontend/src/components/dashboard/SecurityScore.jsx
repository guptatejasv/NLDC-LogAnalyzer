export default function SecurityScore() {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-2xl p-8">
      <h3 className="text-white text-xl font-semibold">Security Score</h3>

      <div className="flex justify-center mt-8">
        <div className="w-44 h-44 rounded-full border-8 border-blue-500 flex items-center justify-center">
          <span className="text-white text-5xl font-bold">92</span>
        </div>
      </div>

      <p className="text-center text-slate-400 mt-6">
        Excellent Security Posture
      </p>
    </div>
  );
}
