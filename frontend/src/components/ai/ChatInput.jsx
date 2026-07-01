import { Send } from "lucide-react";

export default function ChatInput({ value, onChange, onSend }) {
  return (
    <div className="flex gap-3">
      <input
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder="Ask Sentinel AI..."
        className="flex-1 bg-slate-900 border border-slate-700 rounded-xl px-4 py-3 text-white outline-none"
      />

      <button onClick={onSend} className="bg-blue-600 px-5 rounded-xl">
        <Send size={18} />
      </button>
    </div>
  );
}
