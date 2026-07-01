import { motion } from "framer-motion";

export default function KPICard({ title, value, change, icon }) {
  return (
    <motion.div
      whileHover={{ y: -5 }}
      className="bg-slate-900 border border-slate-800 rounded-2xl p-6"
    >
      <div className="flex justify-between items-center">
        <div>
          <p className="text-slate-400 text-sm">{title}</p>

          <h2 className="text-3xl font-bold text-white mt-2">{value}</h2>

          <p className="text-green-400 mt-2 text-sm">{change}</p>
        </div>

        <div>{icon}</div>
      </div>
    </motion.div>
  );
}
