import { BrowserRouter, Routes, Route } from "react-router-dom";

import Dashboard from "../pages/Dashboard";
import Incidents from "../pages/Incidents";
import AIInvestigator from "../pages/AIInvestigator";
import Reports from "../pages/Reports";
import Upload from "../pages/Upload";
import Settings from "../pages/Settings";

export default function AppRoutes() {
  return (
    <BrowserRouter>
      <Routes>
        {/* <Route path="/" element={<Dashboard />} />
        <Route path="/incidents" element={<Incidents />} />
        <Route path="/investigator" element={<AIInvestigator />} />
        <Route path="/reports" element={<Reports />} /> */}
        <Route path="/" element={<Upload />} />
        {/* <Route path="/settings" element={<Settings />} /> */}
      </Routes>
    </BrowserRouter>
  );
}
