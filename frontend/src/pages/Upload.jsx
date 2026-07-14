import { useState, useMemo } from "react";
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from "recharts";

import MainLayout from "../layouts/MainLayout";
import UploadDropzone from "../components/upload/UploadDropzone";
import UploadProgress from "../components/upload/UploadProgress";

const CLASSIFICATION_COLORS = {
  MALICIOUS: "#dc2626",
  SUSPICIOUS: "#f59e0b",
  NORMAL_TRAFFIC_CDN: "#2563eb",
  CLEAN: "#16a34a",
  UNKNOWN: "#94a3b8",
};

const ACTION_COLORS = [
  "#dc2626",
  "#f59e0b",
  "#2563eb",
  "#16a34a",
  "#7c3aed",
  "#0891b2",
  "#db2777",
  "#65a30d",
  "#ea580c",
  "#4f46e5",
  "#059669",
  "#be123c",
  "#0284c7",
];

export default function Upload() {
  const [file, setFile] = useState(null);
  const [progress, setProgress] = useState(0);
  const [step, setStep] = useState(-1);

  // IP threat-intel results
  const [ipResults, setIpResults] = useState([]);
  const [commAnalysis, setCommAnalysis] = useState(null);

  // Executive AI report (streamed)
  const [execRawText, setExecRawText] = useState("");
  const [execReport, setExecReport] = useState(null);
  const [execLoading, setExecLoading] = useState(false);
  const [execError, setExecError] = useState(null);

  const analyzeLogs = async () => {
    if (!file) return;

    try {
      const formData = new FormData();
      formData.append("file", file);

      setProgress(20);

      const response = await fetch("http://127.0.0.1:8000/analyze", {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        throw new Error("Failed to analyze logs");
      }

      setProgress(70);

      const data = await response.json();
      console.log("Backend Response:", data);

      const rawArray = Array.isArray(data.ip) ? data.ip : [];
      const comms = rawArray.find((item) => item.communication_analysis);
      const ips = rawArray.filter((item) => item.ip);

      setCommAnalysis(comms?.communication_analysis ?? null);
      setIpResults(ips);
      setProgress(100);

      let current = 0;
      const interval = setInterval(() => {
        setStep(current);
        current++;
        if (current > 4) clearInterval(interval);
      }, 1000);

      if (data.session_id) {
        streamExecutiveReport(data.session_id);
      }
    } catch (err) {
      console.error(err);
    }
  };

  const streamExecutiveReport = async (sessionId) => {
    setExecLoading(true);
    setExecError(null);
    setExecRawText("");
    setExecReport(null);

    try {
      const response = await fetch(
        `http://127.0.0.1:8000/analyze/${sessionId}/executive-report/stream`,
      );

      if (!response.ok || !response.body) {
        throw new Error("Failed to start executive report stream");
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const parts = buffer.split("\n\n");
        buffer = parts.pop();

        for (const part of parts) {
          const line = part.trim();
          if (!line.startsWith("data:")) continue;

          const jsonStr = line.slice(5).trim();
          let payload;
          try {
            payload = JSON.parse(jsonStr);
          } catch {
            continue;
          }

          if (payload.type === "token") {
            setExecRawText((prev) => prev + payload.content);
          } else if (payload.type === "done") {
            if (payload.report) {
              setExecReport(payload.report);
            } else if (payload.parse_error) {
              setExecError(
                "The AI report could not be parsed as JSON. Showing raw output below.",
              );
            }
            setExecLoading(false);
          } else if (payload.type === "error") {
            setExecError(
              payload.message || "Executive report generation failed.",
            );
            setExecLoading(false);
          }
        }
      }
    } catch (err) {
      console.error(err);
      setExecError(
        err.message || "Something went wrong while streaming the report.",
      );
      setExecLoading(false);
    }
  };

  // ---------- Derived analytics ----------

  const classificationCounts = useMemo(() => {
    const counts = {};
    ipResults.forEach((item) => {
      const key = item.classification || "UNKNOWN";
      counts[key] = (counts[key] || 0) + 1;
    });
    return Object.entries(counts).map(([name, value]) => ({ name, value }));
  }, [ipResults]);

  const commActionData = useMemo(() => {
    if (!commAnalysis?.communication_by_action) return [];
    const merged = {};
    Object.values(commAnalysis.communication_by_action).forEach((actions) => {
      Object.entries(actions).forEach(([action, count]) => {
        merged[action] = (merged[action] || 0) + count;
      });
    });
    return Object.entries(merged)
      .map(([action, count]) => ({ action, count }))
      .sort((a, b) => b.count - a.count);
  }, [commAnalysis]);

  const topThreats = useMemo(() => {
    return ipResults
      .filter((item) =>
        ["MALICIOUS", "SUSPICIOUS"].includes(item.classification),
      )
      .map((item) => ({
        ip: item.ip,
        confidence: item.abuseipdb?.abuseConfidenceScore || 0,
        malicious: item.virustotal?.malicious || 0,
        classification: item.classification,
      }))
      .sort((a, b) => b.confidence - a.confidence)
      .slice(0, 8);
  }, [ipResults]);

  const totalThreats = useMemo(
    () =>
      ipResults.filter((i) =>
        ["MALICIOUS", "SUSPICIOUS"].includes(i.classification),
      ).length,
    [ipResults],
  );

  const totalBlocked = useMemo(() => {
    if (!commAnalysis?.communication_by_action) return null;
    let blocked = 0;
    let total = 0;
    Object.values(commAnalysis.communication_by_action).forEach((actions) => {
      Object.entries(actions).forEach(([action, count]) => {
        total += count;
        if (/deny|denied|drop|block/i.test(action)) blocked += count;
      });
    });
    return total > 0 ? Math.round((blocked / total) * 100) : null;
  }, [commAnalysis]);

  const getBadgeColor = (classification) => {
    switch (classification) {
      case "MALICIOUS":
        return "bg-red-100 text-red-700 border border-red-200";
      case "SUSPICIOUS":
        return "bg-amber-100 text-amber-700 border border-amber-200";
      case "NORMAL_TRAFFIC_CDN":
        return "bg-blue-100 text-blue-700 border border-blue-200";
      case "CLEAN":
        return "bg-green-100 text-green-700 border border-green-200";
      default:
        return "bg-slate-100 text-slate-600 border border-slate-200";
    }
  };

  const getRiskColor = (riskLevel) => {
    switch ((riskLevel || "").toLowerCase()) {
      case "critical":
        return "bg-red-600 text-white";
      case "high":
        return "bg-red-500 text-white";
      case "medium":
        return "bg-amber-500 text-white";
      case "low":
        return "bg-green-600 text-white";
      default:
        return "bg-slate-400 text-white";
    }
  };

  return (
    <MainLayout>
      <div className="bg-slate-50 min-h-screen -m-6 p-6">
        <h1 className="text-4xl text-slate-900 font-bold">Upload Logs</h1>

        <div className="mt-8">
          <UploadDropzone
            onFileSelect={(selectedFile) => setFile(selectedFile)}
          />

          {file && (
            <>
              <p className="text-slate-700 mt-6">Selected File: {file.name}</p>
              <UploadProgress progress={progress} />

              <button
                onClick={analyzeLogs}
                className="mt-4 bg-blue-600 hover:bg-blue-700 px-6 py-3 rounded-xl text-white font-medium transition shadow-sm"
              >
                Analyze
              </button>
            </>
          )}

          {/* ===================== STAT CARDS ===================== */}
          {ipResults.length > 0 && (
            <div className="mt-10 grid grid-cols-2 md:grid-cols-4 gap-4">
              <StatCard
                label="Total IPs Analyzed"
                value={ipResults.length}
                accent="text-slate-900"
              />
              <StatCard
                label="Active Threats"
                value={totalThreats}
                accent="text-red-600"
              />
              <StatCard
                label="Traffic Blocked"
                value={totalBlocked !== null ? `${totalBlocked}%` : "—"}
                accent="text-blue-600"
              />
              <StatCard
                label="Risk Level"
                value={execReport?.risk_level || (execLoading ? "..." : "—")}
                accent="text-amber-600"
              />
            </div>
          )}

          {/* ===================== CHARTS ===================== */}
          {ipResults.length > 0 && (
            <div className="mt-8 grid lg:grid-cols-2 gap-6">
              {/* Classification donut */}
              <div className="bg-white rounded-2xl p-6 border border-slate-200 shadow-sm">
                <h3 className="text-lg font-bold text-slate-900 mb-1">
                  IP Classification Breakdown
                </h3>
                <p className="text-slate-500 text-sm mb-4">
                  Distribution of threat classifications across analyzed IPs
                </p>
                <ResponsiveContainer width="100%" height={280}>
                  <PieChart>
                    <Pie
                      data={classificationCounts}
                      dataKey="value"
                      nameKey="name"
                      cx="50%"
                      cy="50%"
                      innerRadius={60}
                      outerRadius={95}
                      paddingAngle={2}
                    >
                      {classificationCounts.map((entry) => (
                        <Cell
                          key={entry.name}
                          fill={CLASSIFICATION_COLORS[entry.name] || "#94a3b8"}
                        />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        background: "#fff",
                        border: "1px solid #e2e8f0",
                        borderRadius: 8,
                      }}
                    />
                    <Legend
                      layout="horizontal"
                      verticalAlign="bottom"
                      wrapperStyle={{ fontSize: 12, color: "#475569" }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              </div>

              {/* Communication actions bar chart */}
              {commActionData.length > 0 && (
                <div className="bg-white rounded-2xl p-6 border border-slate-200 shadow-sm">
                  <h3 className="text-lg font-bold text-slate-900 mb-1">
                    Firewall Action Breakdown
                  </h3>
                  <p className="text-slate-500 text-sm mb-4">
                    Outbound connection events grouped by firewall action
                  </p>
                  <ResponsiveContainer width="100%" height={280}>
                    <BarChart data={commActionData} margin={{ left: -10 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                      <XAxis
                        dataKey="action"
                        tick={{ fontSize: 11, fill: "#64748b" }}
                        angle={-30}
                        textAnchor="end"
                        interval={0}
                        height={60}
                      />
                      <YAxis tick={{ fontSize: 11, fill: "#64748b" }} />
                      <Tooltip
                        contentStyle={{
                          background: "#fff",
                          border: "1px solid #e2e8f0",
                          borderRadius: 8,
                        }}
                      />
                      <Bar dataKey="count" radius={[6, 6, 0, 0]}>
                        {commActionData.map((entry, i) => (
                          <Cell
                            key={entry.action}
                            fill={ACTION_COLORS[i % ACTION_COLORS.length]}
                          />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              )}

              {/* Top threats by confidence */}
              {topThreats.length > 0 && (
                <div className="bg-white rounded-2xl p-6 border border-slate-200 shadow-sm lg:col-span-2">
                  <h3 className="text-lg font-bold text-slate-900 mb-1">
                    Top Threats by AbuseIPDB Confidence
                  </h3>
                  <p className="text-slate-500 text-sm mb-4">
                    Highest-risk IPs ranked by reported abuse confidence score
                  </p>
                  <ResponsiveContainer width="100%" height={280}>
                    <BarChart
                      data={topThreats}
                      layout="vertical"
                      margin={{ left: 20 }}
                    >
                      <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                      <XAxis
                        type="number"
                        domain={[0, 100]}
                        tick={{ fontSize: 11, fill: "#64748b" }}
                      />
                      <YAxis
                        type="category"
                        dataKey="ip"
                        width={130}
                        tick={{ fontSize: 12, fill: "#334155" }}
                      />
                      <Tooltip
                        contentStyle={{
                          background: "#fff",
                          border: "1px solid #e2e8f0",
                          borderRadius: 8,
                        }}
                        formatter={(value, name) => [
                          `${value}${name === "confidence" ? "%" : ""}`,
                          name,
                        ]}
                      />
                      <Bar dataKey="confidence" radius={[0, 6, 6, 0]}>
                        {topThreats.map((entry) => (
                          <Cell
                            key={entry.ip}
                            fill={
                              entry.classification === "MALICIOUS"
                                ? "#dc2626"
                                : "#f59e0b"
                            }
                          />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              )}
            </div>
          )}

          {/* ===================== EXECUTIVE AI REPORT ===================== */}
          {(execLoading || execReport || execRawText || execError) && (
            <div className="mt-10">
              <h2 className="text-2xl font-bold text-slate-900 mb-6">
                Executive SOC Report
              </h2>

              {execError && (
                <div className="bg-red-50 border border-red-200 rounded-xl p-4 mb-6 text-red-700">
                  {execError}
                </div>
              )}

              {execLoading && !execReport && (
                <div className="bg-white rounded-2xl p-6 border border-slate-200 shadow-sm mb-6">
                  <div className="flex items-center gap-2 mb-4">
                    <span className="h-2 w-2 rounded-full bg-blue-500 animate-pulse" />
                    <p className="text-blue-600 font-semibold text-sm">
                      Generating report...
                    </p>
                  </div>
                  <pre className="text-slate-600 text-sm whitespace-pre-wrap font-mono max-h-96 overflow-y-auto">
                    {execRawText}
                  </pre>
                </div>
              )}

              {!execLoading && execError && execRawText && !execReport && (
                <div className="bg-white rounded-2xl p-6 border border-slate-200 shadow-sm mb-6">
                  <pre className="text-slate-600 text-sm whitespace-pre-wrap font-mono max-h-96 overflow-y-auto">
                    {execRawText}
                  </pre>
                </div>
              )}

              {execReport && (
                <div className="space-y-6">
                  {/* Summary */}
                  <div className="bg-white rounded-2xl p-6 border border-slate-200 shadow-sm">
                    <div className="flex items-center justify-between mb-4">
                      <h3 className="text-lg font-bold text-slate-900">
                        Executive Summary
                      </h3>
                      <span
                        className={`px-4 py-1.5 rounded-full text-xs font-bold tracking-wide ${getRiskColor(
                          execReport.risk_level,
                        )}`}
                      >
                        {execReport.risk_level?.toUpperCase()} RISK
                      </span>
                    </div>
                    <p className="text-slate-700 leading-relaxed">
                      {execReport.executive_summary}
                    </p>
                    {execReport.overall_assessment && (
                      <p className="text-slate-500 leading-relaxed mt-4 pt-4 border-t border-slate-100">
                        {execReport.overall_assessment}
                      </p>
                    )}
                  </div>

                  {/* IOC summary */}
                  {execReport.ioc_summary && (
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                      <StatCard
                        label="Malicious"
                        value={execReport.ioc_summary.malicious_ips ?? 0}
                        accent="text-red-600"
                      />
                      <StatCard
                        label="Suspicious"
                        value={execReport.ioc_summary.suspicious_ips ?? 0}
                        accent="text-amber-600"
                      />
                      <StatCard
                        label="Clean"
                        value={execReport.ioc_summary.clean_ips ?? 0}
                        accent="text-green-600"
                      />
                      <StatCard
                        label="Unknown"
                        value={execReport.ioc_summary.unknown_ips ?? 0}
                        accent="text-slate-500"
                      />
                    </div>
                  )}

                  {/* Findings + Attack patterns */}
                  <div className="grid md:grid-cols-2 gap-6">
                    {execReport.findings?.length > 0 && (
                      <ListCard
                        title="Findings"
                        items={execReport.findings}
                        bullet="•"
                      />
                    )}
                    {execReport.attack_patterns?.length > 0 && (
                      <div className="bg-white rounded-2xl p-6 border border-slate-200 shadow-sm">
                        <h3 className="text-lg font-bold text-slate-900 mb-4">
                          Attack Patterns
                        </h3>
                        <div className="space-y-3">
                          {execReport.attack_patterns.map((ap, i) => (
                            <div
                              key={i}
                              className="bg-red-50 border border-red-100 rounded-lg p-4"
                            >
                              <h4 className="text-red-700 font-bold text-sm mb-1">
                                {ap.pattern}
                              </h4>
                              <p className="text-slate-600 text-sm">
                                {ap.description}
                              </p>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Anomalies + Suspicious behaviors */}
                  <div className="grid md:grid-cols-2 gap-6">
                    {execReport.anomalies?.length > 0 && (
                      <ListCard
                        title="Anomalies"
                        items={execReport.anomalies}
                        bullet="▲"
                        accent="text-amber-600"
                      />
                    )}
                    {execReport.suspicious_behaviors?.length > 0 && (
                      <ListCard
                        title="Suspicious Behaviors"
                        items={execReport.suspicious_behaviors}
                        bullet="⚠"
                        accent="text-red-600"
                      />
                    )}
                  </div>

                  {/* Possible attack types as pills */}
                  {execReport.possible_attack_types?.length > 0 && (
                    <div className="bg-white rounded-2xl p-6 border border-slate-200 shadow-sm">
                      <h3 className="text-lg font-bold text-slate-900 mb-4">
                        Possible Attack Types
                      </h3>
                      <div className="flex flex-wrap gap-2">
                        {execReport.possible_attack_types.map((type, i) => (
                          <span
                            key={i}
                            className="px-3 py-1.5 bg-slate-100 border border-slate-200 text-slate-700 text-sm rounded-full font-medium"
                          >
                            {type}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* MITRE ATT&CK mapping */}
                  {execReport.mitre_attack?.length > 0 && (
                    <div className="bg-white rounded-2xl p-6 border border-slate-200 shadow-sm">
                      <h3 className="text-lg font-bold text-slate-900 mb-4">
                        MITRE ATT&CK Mapping
                      </h3>
                      <div className="overflow-x-auto">
                        <table className="w-full text-sm">
                          <thead>
                            <tr className="text-left text-slate-500 border-b border-slate-200">
                              <th className="pb-2 font-semibold">ID</th>
                              <th className="pb-2 font-semibold">Tactic</th>
                              <th className="pb-2 font-semibold">Technique</th>
                            </tr>
                          </thead>
                          <tbody>
                            {execReport.mitre_attack.map((m, i) => (
                              <tr
                                key={i}
                                className="border-b border-slate-100 last:border-0"
                              >
                                <td className="py-2.5">
                                  <span className="font-mono text-blue-600 bg-blue-50 px-2 py-0.5 rounded text-xs">
                                    {m.id}
                                  </span>
                                </td>
                                <td className="py-2.5 text-slate-700">
                                  {m.tactic}
                                </td>
                                <td className="py-2.5 text-slate-700">
                                  {m.technique}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  )}

                  {/* Timeline + comms narrative */}
                  <div className="grid md:grid-cols-2 gap-6">
                    {execReport.timeline_analysis && (
                      <div className="bg-white rounded-2xl p-6 border border-slate-200 shadow-sm">
                        <h3 className="text-lg font-bold text-slate-900 mb-3">
                          Timeline Analysis
                        </h3>
                        <p className="text-slate-600 text-sm leading-relaxed">
                          {execReport.timeline_analysis}
                        </p>
                      </div>
                    )}
                    {execReport.communication_analysis && (
                      <div className="bg-white rounded-2xl p-6 border border-slate-200 shadow-sm">
                        <h3 className="text-lg font-bold text-slate-900 mb-3">
                          Communication Analysis
                        </h3>
                        <p className="text-slate-600 text-sm leading-relaxed">
                          {execReport.communication_analysis}
                        </p>
                      </div>
                    )}
                  </div>

                  {/* Recommended + priority actions */}
                  <div className="grid md:grid-cols-2 gap-6">
                    {execReport.recommended_actions?.length > 0 && (
                      <ListCard
                        title="Recommended Actions"
                        items={execReport.recommended_actions}
                        bullet="✓"
                        accent="text-blue-600"
                      />
                    )}
                    {execReport.priority_actions?.length > 0 && (
                      <ListCard
                        title="Priority Actions"
                        items={execReport.priority_actions}
                        bullet="!"
                        accent="text-red-600"
                        emphasize
                      />
                    )}
                  </div>

                  {/* Affected assets */}
                  {execReport.affected_assets?.length > 0 && (
                    <ListCard
                      title="Affected Assets"
                      items={execReport.affected_assets}
                      bullet="◆"
                    />
                  )}
                </div>
              )}
            </div>
          )}

          {/* ===================== PER-IP RESULTS ===================== */}
          {ipResults.length > 0 && (
            <div className="mt-10">
              <h2 className="text-2xl font-bold text-slate-900 mb-6">
                Per-IP Analysis
              </h2>

              <div className="grid gap-4">
                {ipResults.map((item, index) => (
                  <div
                    key={item.ip || index}
                    className="bg-white rounded-2xl p-6 border border-slate-200 shadow-sm"
                  >
                    <div className="flex justify-between items-center mb-4">
                      <div>
                        <h3 className="text-xl font-bold text-slate-900">
                          {item.ip}
                        </h3>
                        <p className="text-slate-500 text-sm">
                          {item.reasoning}
                        </p>
                      </div>
                      <span
                        className={`px-3 py-1.5 rounded-full text-xs font-bold ${getBadgeColor(
                          item.classification,
                        )}`}
                      >
                        {item.classification}
                      </span>
                    </div>

                    <div className="grid md:grid-cols-2 gap-4">
                      <div className="bg-slate-50 rounded-lg p-4 border border-slate-100">
                        <h4 className="text-sm font-bold text-blue-600 mb-3">
                          VirusTotal
                        </h4>
                        <div className="space-y-1.5 text-slate-600 text-sm">
                          <p>
                            <span className="text-slate-400">Status:</span>{" "}
                            {item.virustotal?.status}
                          </p>
                          <p>
                            <span className="text-slate-400">Country:</span>{" "}
                            {item.virustotal?.country}
                          </p>
                          <p>
                            <span className="text-slate-400">ASN:</span>{" "}
                            {item.virustotal?.asn}
                          </p>
                          <p>
                            <span className="text-slate-400">Malicious:</span>{" "}
                            {item.virustotal?.malicious}
                          </p>
                          <p>
                            <span className="text-slate-400">Suspicious:</span>{" "}
                            {item.virustotal?.suspicious}
                          </p>
                          <p>
                            <span className="text-slate-400">Harmless:</span>{" "}
                            {item.virustotal?.harmless}
                          </p>
                          <p>
                            <span className="text-slate-400">Undetected:</span>{" "}
                            {item.virustotal?.undetected}
                          </p>
                        </div>
                      </div>

                      <div className="bg-slate-50 rounded-lg p-4 border border-slate-100">
                        <h4 className="text-sm font-bold text-red-600 mb-3">
                          AbuseIPDB
                        </h4>
                        <div className="space-y-1.5 text-slate-600 text-sm">
                          <p>
                            <span className="text-slate-400">Status:</span>{" "}
                            {item.abuseipdb?.status}
                          </p>
                          <p>
                            <span className="text-slate-400">Confidence:</span>{" "}
                            {item.abuseipdb?.abuseConfidenceScore}%
                          </p>
                          <p>
                            <span className="text-slate-400">
                              Total Reports:
                            </span>{" "}
                            {item.abuseipdb?.totalReports}
                          </p>
                          <p>
                            <span className="text-slate-400">ISP:</span>{" "}
                            {item.abuseipdb?.isp}
                          </p>
                          <p>
                            <span className="text-slate-400">Domain:</span>{" "}
                            {item.abuseipdb?.domain}
                          </p>
                          <p>
                            <span className="text-slate-400">Usage:</span>{" "}
                            {item.abuseipdb?.usageType}
                          </p>
                          <p>
                            <span className="text-slate-400">
                              Last Reported:
                            </span>{" "}
                            {item.abuseipdb?.lastReportedAt}
                          </p>
                        </div>
                      </div>
                    </div>

                    <div className="mt-4 pt-3 border-t border-slate-100 text-slate-400 text-xs">
                      Timestamp: {item.timestamp}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </MainLayout>
  );
}

function StatCard({ label, value, accent }) {
  return (
    <div className="bg-white rounded-2xl p-5 border border-slate-200 shadow-sm">
      <p className={`text-3xl font-bold ${accent}`}>{value}</p>
      <p className="text-slate-500 text-sm mt-1">{label}</p>
    </div>
  );
}

function ListCard({
  title,
  items,
  bullet = "•",
  accent = "text-slate-600",
  emphasize = false,
}) {
  return (
    <div className="bg-white rounded-2xl p-6 border border-slate-200 shadow-sm">
      <h3 className="text-lg font-bold text-slate-900 mb-4">{title}</h3>
      <ul className="space-y-2.5">
        {items.map((item, i) => (
          <li key={i} className="flex gap-2 text-sm">
            <span className={`${accent} font-bold`}>{bullet}</span>
            <span
              className={
                emphasize ? "text-slate-800 font-medium" : "text-slate-600"
              }
            >
              {item}
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}
