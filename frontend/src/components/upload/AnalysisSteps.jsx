const steps = [
  "Parsing Logs",
  "Risk Analysis",
  "MITRE Mapping",
  "AI Investigation",
  "Generating Report",
];

export default function AnalysisSteps({ currentStep }) {
  return (
    <div className="space-y-4 mt-8">
      {steps.map((step, index) => (
        <div
          key={step}
          className={`p-4 rounded-xl ${
            index <= currentStep ? "bg-blue-600" : "bg-slate-800"
          }`}
        >
          {step}
        </div>
      ))}
    </div>
  );
}
