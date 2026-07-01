export default function UploadProgress({ progress }) {
  return (
    <div className="mt-8">
      <div className="flex justify-between">
        <span className="text-white">Upload Progress</span>

        <span className="text-blue-400">{progress}%</span>
      </div>

      <div className="h-3 bg-slate-800 rounded-full mt-2">
        <div
          className="h-full bg-blue-500 rounded-full"
          style={{
            width: `${progress}%`,
          }}
        />
      </div>
    </div>
  );
}
