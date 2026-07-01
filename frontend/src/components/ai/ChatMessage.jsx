export default function ChatMessage({ role, content }) {
  const isUser = role === "user";

  return (
    <div className={`flex ${isUser ? "justify-end" : "justify-start"}`}>
      <div
        className={`max-w-3xl p-4 rounded-2xl ${
          isUser ? "bg-blue-600 text-white" : "bg-slate-800 text-slate-200"
        }`}
      >
        {content}
      </div>
    </div>
  );
}
