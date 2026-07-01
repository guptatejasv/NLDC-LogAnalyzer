import { useState } from "react";

import MainLayout from "../layouts/MainLayout";
import UploadDropzone from "../components/upload/UploadDropzone";
import UploadProgress from "../components/upload/UploadProgress";
// import AnalysisSteps from "../components/upload/AnalysisSteps";

export default function Upload() {
  const [file, setFile] = useState(null);
  const [progress, setProgress] = useState(0);
  const [step, setStep] = useState(-1);
  const [result, setResult] = useState(null);

  const simulateAnalysis = async () => {
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

      console.log("Backend Response:", data.ip);

      setResult(data.ip);

      setProgress(100);

      let current = 0;

      const interval = setInterval(() => {
        setStep(current);
        current++;

        if (current > 4) {
          clearInterval(interval);
        }
      }, 1000);
    } catch (err) {
      console.error(err);
    }
  };

  const getBadgeColor = (classification) => {
    switch (classification) {
      case "MALICIOUS":
        return "bg-red-600";

      case "SUSPICIOUS":
        return "bg-yellow-500 text-black";

      case "NORMAL_TRAFFIC_CDN":
        return "bg-blue-600";

      case "CLEAN":
        return "bg-green-600";

      default:
        return "bg-gray-600";
    }
  };

  return (
    <MainLayout>
      <h1 className="text-4xl text-white font-bold">Upload Logs</h1>

      <div className="mt-8">
        <UploadDropzone
          onFileSelect={(selectedFile) => setFile(selectedFile)}
        />

        {file && (
          <>
            <p className="text-white mt-6">Selected File: {file.name}</p>

            <UploadProgress progress={progress} />

            <button
              onClick={simulateAnalysis}
              className="mt-4 bg-blue-600 hover:bg-blue-700 px-6 py-3 rounded-xl text-white transition"
            >
              Analyze
            </button>

            {/* <AnalysisSteps currentStep={step} /> */}
          </>
        )}

        {result && (
          <div className="mt-10">
            <h2 className="text-3xl font-bold text-white mb-6">
              Analysis Results
            </h2>

            <div className="bg-slate-900 rounded-xl p-4 mb-6">
              <h3 className="text-xl text-white">
                Total Destination IPs :{" "}
                <span className="font-bold text-blue-400">{result.count}</span>
              </h3>
            </div>

            <div className="grid gap-6">
              {result.ip?.map((item, index) => (
                <div
                  key={index}
                  className="bg-slate-900 rounded-xl p-6 border border-slate-700 shadow-lg"
                >
                  {/* Header */}

                  <div className="flex justify-between items-center mb-4">
                    <div>
                      <h3 className="text-2xl font-bold text-white">
                        {item.ip}
                      </h3>

                      <p className="text-gray-400">{item.reasoning}</p>
                    </div>

                    <span
                      className={`px-4 py-2 rounded-full text-sm font-bold ${getBadgeColor(
                        item.classification,
                      )}`}
                    >
                      {item.classification}
                    </span>
                  </div>

                  {/* VirusTotal */}

                  <div className="grid md:grid-cols-2 gap-6">
                    <div className="bg-slate-800 rounded-lg p-4">
                      <h4 className="text-lg font-bold text-blue-400 mb-3">
                        VirusTotal
                      </h4>

                      <div className="space-y-2 text-gray-300">
                        <p>
                          <strong>Status:</strong> {item.virustotal?.status}
                        </p>

                        <p>
                          <strong>Country:</strong> {item.virustotal?.country}
                        </p>

                        <p>
                          <strong>ASN:</strong> {item.virustotal?.asn}
                        </p>

                        <p>
                          <strong>Malicious:</strong>{" "}
                          {item.virustotal?.malicious}
                        </p>

                        <p>
                          <strong>Suspicious:</strong>{" "}
                          {item.virustotal?.suspicious}
                        </p>

                        <p>
                          <strong>Harmless:</strong> {item.virustotal?.harmless}
                        </p>

                        <p>
                          <strong>Undetected:</strong>{" "}
                          {item.virustotal?.undetected}
                        </p>
                      </div>
                    </div>

                    {/* AbuseIPDB */}

                    <div className="bg-slate-800 rounded-lg p-4">
                      <h4 className="text-lg font-bold text-red-400 mb-3">
                        AbuseIPDB
                      </h4>

                      <div className="space-y-2 text-gray-300">
                        <p>
                          <strong>Status:</strong> {item.abuseipdb?.status}
                        </p>

                        <p>
                          <strong>Confidence:</strong>{" "}
                          {item.abuseipdb?.abuseConfidenceScore}%
                        </p>

                        <p>
                          <strong>Total Reports:</strong>{" "}
                          {item.abuseipdb?.totalReports}
                        </p>

                        <p>
                          <strong>ISP:</strong> {item.abuseipdb?.isp}
                        </p>

                        <p>
                          <strong>Domain:</strong> {item.abuseipdb?.domain}
                        </p>

                        <p>
                          <strong>Usage:</strong> {item.abuseipdb?.usageType}
                        </p>

                        <p>
                          <strong>Last Reported:</strong>{" "}
                          {item.abuseipdb?.lastReportedAt}
                        </p>
                      </div>
                    </div>
                  </div>

                  {/* Footer */}

                  <div className="mt-5 pt-4 border-t border-slate-700 text-gray-400 text-sm">
                    Timestamp : {item.timestamp}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </MainLayout>
  );
}
