import { Navigate, Route, Routes } from "react-router-dom";
import { ProtectedRoute } from "./auth/ProtectedRoute";
import { AppLayout } from "./layout/AppLayout";
import { DashboardPage } from "./pages/DashboardPage";
import { DirectoryPage } from "./pages/DirectoryPage";
import { EndpointDetailPage } from "./pages/EndpointDetailPage";
import { EndpointHistoryPage } from "./pages/EndpointHistoryPage";
import { EndpointListPage } from "./pages/EndpointListPage";
import { GroupsPage } from "./pages/GroupsPage";
import { LoginPage } from "./pages/LoginPage";
import { UnderDevelopment } from "./pages/UnderDevelopment";
import { ThemeProvider } from "./theme/ThemeProvider";

export function App() {
  return (
    // UI-level provider: mounted inside App so every render path (tests
    // included) has theme state without depending on main.tsx wiring.
    <ThemeProvider>
      <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route element={<ProtectedRoute />}>
        <Route element={<AppLayout />}>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/endpoints" element={<EndpointListPage />} />
          <Route path="/endpoints/:id" element={<EndpointDetailPage />} />
          <Route path="/endpoints/:id/history" element={<EndpointHistoryPage />} />
          <Route path="/groups" element={<GroupsPage />} />
          <Route path="/active-directory" element={<DirectoryPage />} />
          <Route
            path="/security"
            element={<UnderDevelopment moduleName="Security & Compliance" />}
          />
          <Route
            path="/vulnerabilities"
            element={<UnderDevelopment moduleName="Vulnerabilities" />}
          />
          <Route
            path="/network"
            element={<UnderDevelopment moduleName="Network" />}
          />
          <Route
            path="/dns"
            element={<UnderDevelopment moduleName="DNS Security" />}
          />
          <Route
            path="/automation"
            element={<UnderDevelopment moduleName="Automation" />}
          />
          <Route path="/assets" element={<UnderDevelopment moduleName="Assets" />} />
          <Route
            path="/reports"
            element={<UnderDevelopment moduleName="Reports" />}
          />
          <Route
            path="/admin"
            element={<UnderDevelopment moduleName="Administration" />}
          />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Route>
      </Routes>
    </ThemeProvider>
  );
}
