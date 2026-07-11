import React from 'react'
import { Outlet, useNavigate, useLocation } from 'react-router-dom'
import { Layout, Menu, Typography } from 'antd'
import {
  DashboardOutlined,
  AlertOutlined,
  CloudServerOutlined,
  SafetyOutlined
} from '@ant-design/icons'

const { Header, Sider, Content } = Layout
const { Title } = Typography

const menuItems = [
  { key: '/dashboard', icon: <DashboardOutlined />, label: '攻击大盘' },
  { key: '/alarms', icon: <AlertOutlined />, label: '告警列表' },
  { key: '/agents', icon: <CloudServerOutlined />, label: 'Agent 管理' }
]

export default function AppLayout() {
  const navigate = useNavigate()
  const location = useLocation()

  return (
    <Layout style={{ minHeight: '100vh' }}>
      <Sider theme="dark" collapsible breakpoint="lg">
        <div style={{
          height: 64,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          borderBottom: '1px solid rgba(255,255,255,0.1)'
        }}>
          <SafetyOutlined style={{ fontSize: 28, color: '#1677ff', marginRight: 8 }} />
          <Title level={4} style={{ color: '#fff', margin: 0 }}>RASP Admin</Title>
        </div>
        <Menu
          theme="dark"
          mode="inline"
          selectedKeys={[location.pathname]}
          items={menuItems}
          onClick={({ key }) => navigate(key)}
        />
      </Sider>
      <Layout>
        <Header style={{
          background: '#fff',
          padding: '0 24px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          borderBottom: '1px solid #f0f0f0',
          boxShadow: '0 1px 4px rgba(0,0,0,0.05)'
        }}>
          <Title level={4} style={{ margin: 0 }}>RASP 运行时应用自我保护平台</Title>
          <span style={{ color: '#999', fontSize: 13 }}>v1.0.0</span>
        </Header>
        <Content style={{ margin: 24 }}>
          <Outlet />
        </Content>
      </Layout>
    </Layout>
  )
}
