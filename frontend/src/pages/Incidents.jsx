import MainLayout from "../layouts/MainLayout";

import IncidentFilters from "../components/incidents/IncidentFilters";
import IncidentTable from "../components/incidents/IncidentTable";

export default function Incidents() {
  return (
    <MainLayout>
      <h1 className="text-4xl font-bold text-white">Incidents</h1>

      <p className="text-slate-400 mt-2">
        AI detected threats and investigations
      </p>

      <div className="mt-6">
        <IncidentFilters />
      </div>

      <div className="mt-6">
        <IncidentTable />
      </div>
    </MainLayout>
  );
}
