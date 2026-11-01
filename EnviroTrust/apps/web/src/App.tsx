import React from 'react';
import { BrowserRouter, Routes, Route, Navigate, Outlet } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext.js';
import { ProtectedRoute } from './components/common/ProtectedRoute.js';
import { Navbar } from './components/common/Navbar.js';
import { Sidebar } from './components/common/Sidebar.js';

import { LoginPage } from './pages/LoginPage.js';
import { OverviewPage } from './pages/OverviewPage.js';
import { MonitoringPage } from './pages/MonitoringPage.js';
import { SensorsPage } from './pages/SensorsPage.js';
import { AnomaliesPage } from './pages/AnomaliesPage.js';
import { AuditPage } from './pages/AuditPage.js';
import { AlertsPage } from './pages/AlertsPage.js';
import { UsersPage } from './pages/UsersPage.js';
import { AttackLabPage } from './pages/AttackLabPage.js';

const AppLayout: React.FC = () => {
  return (
    <div className="app-container">
      <Sidebar />
      <div className="main-viewport">
        <Navbar />
        <main className="content-area">
          <Outlet />
        </main>
      </div>
    </div>
  );
};

export const App: React.FC = () => {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          {/* Public login route */}
          <Route path="/login" element={<LoginPage />} />

          {/* Authenticated application routes */}
          <Route
            element={
              <ProtectedRoute>
                <AppLayout />
              </ProtectedRoute>
            }
          >
            <Route index element={<OverviewPage />} />
            <Route path="overview" element={<OverviewPage />} />
            <Route path="monitoring" element={<MonitoringPage />} />
            <Route path="sensors" element={<SensorsPage />} />
            <Route path="anomalies" element={<AnomaliesPage />} />
            <Route path="alerts" element={<AlertsPage />} />
            <Route path="audit" element={<AuditPage />} />
            {/* Demo-only lab: all roles may read evidence; the server restricts execution to authorized demo admins */}
            <Route path="attack-lab" element={<AttackLabPage />} />

            {/* Platform Admin Only */}
            <Route
              path="users"
              element={
                <ProtectedRoute allowedRoles={['PLATFORM_ADMIN']}>
                  <UsersPage />
                </ProtectedRoute>
              }
            />
          </Route>

          {/* Catch-all redirect */}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
};

