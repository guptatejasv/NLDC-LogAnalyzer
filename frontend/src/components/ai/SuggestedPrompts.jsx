const prompts = [
  "Why is this incident critical?",
  "Show attack timeline",
  "Show evidence",
  "Suggest remediation",
  "Generate executive report",
];

export default function SuggestedPrompts({ onSelect }) {
  return (
    <div className="flex flex-wrap gap-3">
      {prompts.map((prompt) => (
        <button
          key={prompt}
          onClick={() => onSelect(prompt)}
          className="bg-slate-800 hover:bg-slate-700 px-4 py-2 rounded-xl text-slate-200"
        >
          {prompt}
        </button>
      ))}
    </div>
  );
}
