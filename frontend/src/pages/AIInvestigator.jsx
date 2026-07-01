import { useState } from "react";

import MainLayout from "../layouts/MainLayout";

import ChatMessage from "../components/ai/ChatMessage";
import ChatInput from "../components/ai/ChatInput";
import SuggestedPrompts from "../components/ai/SuggestedPrompts";
import EvidencePanel from "../components/ai/EvidencePanel";
import InvestigationHeader from "../components/ai/InvestigationHeader";

export default function AIInvestigator() {
  const [messages, setMessages] = useState([
    {
      role: "assistant",
      content: "Hello. I'm Sentinel AI. Ask me about your incidents.",
    },
  ]);

  const [input, setInput] = useState("");

  const sendMessage = () => {
    if (!input.trim()) return;

    setMessages((prev) => [
      ...prev,
      {
        role: "user",
        content: input,
      },
      {
        role: "assistant",
        content:
          "Analysis complete. This attack appears related to credential abuse.",
      },
    ]);

    setInput("");
  };

  return (
    <MainLayout>
      <InvestigationHeader />

      <div className="grid grid-cols-4 gap-6">
        <div className="col-span-3">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 h-[700px] flex flex-col">
            <SuggestedPrompts onSelect={(prompt) => setInput(prompt)} />

            <div className="flex-1 overflow-y-auto mt-6 space-y-4">
              {messages.map((message, index) => (
                <ChatMessage
                  key={index}
                  role={message.role}
                  content={message.content}
                />
              ))}
            </div>

            <ChatInput value={input} onChange={setInput} onSend={sendMessage} />
          </div>
        </div>

        <div>
          <EvidencePanel />
        </div>
      </div>
    </MainLayout>
  );
}
