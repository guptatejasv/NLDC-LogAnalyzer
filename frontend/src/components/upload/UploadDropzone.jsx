import { useDropzone } from "react-dropzone";
import { useState } from "react";
export default function UploadDropzone({ onFileSelect }) {
  const [filename, setFilename] = useState("");
  const { getRootProps, getInputProps } = useDropzone({
    onDrop: (acceptedFiles) => {
      onFileSelect(acceptedFiles[0]);
      setFilename(acceptedFiles[0].name);
    },
  });

  return (
    <div
      {...getRootProps()}
      className="border-2 border-dashed border-slate-700 rounded-2xl p-20 text-center cursor-pointer hover:border-blue-500 transition"
    >
      <input {...getInputProps()} />

      <h2 className="text-2xl text-black">
        {filename
          ? `${filename} Uploaded`
          : "Drag and drop your log file here, or click to select a file to upload."}
      </h2>

      <p className="text-slate-400 mt-3">CSV, JSON, EVTX</p>
    </div>
  );
}
