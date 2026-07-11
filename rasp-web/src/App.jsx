import React from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import AppLayout from './components/Layout'
import Dashboard from './pages/Dashboard'
import Alarms from './pages/Alarms'
import Agents from './pages/Agents'

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<AppLayout />}>
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="dashboard" element={<Dashboard />} />
        <Route path="alarms" element={<Alarms />} />
        <Route path="agents" element={<Agents />} />
      </Route>
    </Routes>
  )
}
