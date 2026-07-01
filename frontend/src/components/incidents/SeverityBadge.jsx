export default function SeverityBadge({ severity }) {
  const styles = {
    Critical: "bg-red-500/20 text-red-400",

    High: "bg-orange-500/20 text-orange-400",

    Medium: "bg-yellow-500/20 text-yellow-400",

    Low: "bg-green-500/20 text-green-400",
  };

  return (
    <span
      className={`px-3 py-1 rounded-full text-sm font-medium ${styles[severity]}`}
    >
      {severity}
    </span>
  );
}
