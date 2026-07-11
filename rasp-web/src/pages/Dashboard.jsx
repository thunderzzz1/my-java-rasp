import React, { useEffect, useState } from 'react'
import { Card, Col, Row, Statistic, Table, Tag, Space, Spin, Typography, Empty } from 'antd'
import {
  AlertOutlined, StopOutlined, SafetyCertificateOutlined,
  RiseOutlined, CloudServerOutlined
} from '@ant-design/icons'
import { fetchDashboardStats, fetchAttackTrend } from '../api'

const { Title, Text } = Typography

const severityColors = { HIGH: 'red', CRITICAL: '#ff4d4f', MEDIUM: 'orange', LOW: 'blue' }
const typeNames = {
  SQL_INJECTION: 'SQL注入', COMMAND_EXEC: '命令执行', DESERIALIZATION: '反序列化',
  FILE_OP: '文件操作', SSRF: 'SSRF', JNDI_INJECTION: 'JNDI注入'
}

export default function Dashboard() {
  const [stats, setStats] = useState(null)
  const [trend, setTrend] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    loadData()
    const timer = setInterval(loadData, 15000) // 15秒刷新
    return () => clearInterval(timer)
  }, [])

  async function loadData() {
    try {
      const [statsRes, trendRes] = await Promise.all([
        fetchDashboardStats(), fetchAttackTrend()
      ])
      setStats(statsRes.data)
      setTrend(trendRes.data)
    } catch (e) {
      console.error('Dashboard load failed:', e)
    } finally {
      setLoading(false)
    }
  }

  if (loading) return <div style={{ textAlign: 'center', padding: 120 }}><Spin size="large" /></div>
  if (!stats) return <Empty description="无法加载数据" />

  return (
    <div>
      {/* 核心指标卡片 */}
      <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
        <Col xs={24} sm={12} lg={6}>
          <Card><Statistic title="总攻击数" value={stats.totalAttacks}
            prefix={<AlertOutlined />} valueStyle={{ color: '#ff4d4f' }} /></Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card><Statistic title="今日攻击" value={stats.todayAttacks}
            prefix={<RiseOutlined />} valueStyle={{ color: '#faad14' }} /></Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card><Statistic title="已阻断" value={stats.blockedCount}
            prefix={<StopOutlined />} valueStyle={{ color: '#52c41a' }} /></Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card><Statistic title="在线 Agent" value={stats.onlineAgents}
            prefix={<CloudServerOutlined />} valueStyle={{ color: '#1677ff' }} /></Card>
        </Col>
      </Row>

      {/* 攻击类型分布 */}
      <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
        <Col xs={24} md={12}>
          <Card title={<><SafetyCertificateOutlined /> 攻击类型分布</>}>
            {stats.attackTypeCounts && Object.keys(stats.attackTypeCounts).length > 0 ? (
              <Space direction="vertical" style={{ width: '100%' }}>
                {Object.entries(stats.attackTypeCounts).map(([type, count]) => (
                  <div key={type} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <Tag color="blue">{typeNames[type] || type}</Tag>
                    <div style={{ flex: 1, margin: '0 12px' }}>
                      <div style={{
                        height: 8, borderRadius: 4, backgroundColor: '#1677ff',
                        width: `${Math.min(100, (count / stats.totalAttacks) * 500)}%`,
                        minWidth: 8
                      }} />
                    </div>
                    <Text strong>{count}</Text>
                  </div>
                ))}
              </Space>
            ) : <Empty description="暂无数据" />}
          </Card>
        </Col>

        {/* 严重级别分布 */}
        <Col xs={24} md={12}>
          <Card title={<><SafetyCertificateOutlined /> 严重级别分布</>}>
            {stats.severityCounts && Object.keys(stats.severityCounts).length > 0 ? (
              <Space direction="vertical" style={{ width: '100%' }}>
                {Object.entries(stats.severityCounts).sort().reverse().map(([sev, count]) => (
                  <div key={sev} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <Tag color={severityColors[sev]}>{sev}</Tag>
                    <div style={{ flex: 1, margin: '0 12px' }}>
                      <div style={{
                        height: 8, borderRadius: 4, backgroundColor: severityColors[sev] || '#999',
                        width: `${Math.min(100, (count / stats.totalAttacks) * 500)}%`,
                        minWidth: 8
                      }} />
                    </div>
                    <Text strong>{count}</Text>
                  </div>
                ))}
              </Space>
            ) : <Empty description="暂无数据" />}
          </Card>
        </Col>
      </Row>

      {/* 攻击趋势 */}
      <Card title={<><RiseOutlined /> 24小时攻击趋势</>}>
        {trend && trend.trendData && trend.trendData.length > 0 ? (
          <div>
            <div style={{ display: 'flex', alignItems: 'flex-end', gap: 4, height: 200, padding: '12px 0' }}>
              {trend.trendData.slice(-48).map((point, i) => (
                <div key={i} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                  <div style={{
                    width: '100%', maxWidth: 20, borderRadius: '2px 2px 0 0',
                    backgroundColor: '#1677ff', height: Math.max(4, (point.count / Math.max(1, trend.peakCount)) * 180)
                  }} />
                  {i % 6 === 0 && <Text style={{ fontSize: 10, marginTop: 4, transform: 'rotate(-45deg)', whiteSpace: 'nowrap' }}>
                    {point.hour?.split(' ')[1] || point.hour}
                  </Text>}
                </div>
              ))}
            </div>
            <div style={{ marginTop: 8 }}>
              <Text type="secondary">峰值: <Text strong>{trend.peakHour}</Text> — <Text strong>{trend.peakCount} 次</Text></Text>
            </div>
          </div>
        ) : <Empty description="暂无趋势数据" />}
      </Card>
    </div>
  )
}
