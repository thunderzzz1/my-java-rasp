import React, { useEffect, useState } from 'react'
import { Card, Table, Tag, Space, Button, message, Typography } from 'antd'
import { ReloadOutlined, CheckCircleOutlined, CloseCircleOutlined } from '@ant-design/icons'
import { fetchAgents } from '../api'
import dayjs from 'dayjs'

const { Text } = Typography

export default function Agents() {
  const [agents, setAgents] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => { loadAgents() }, [])

  async function loadAgents() {
    setLoading(true);
    try {
      const res = await fetchAgents()
      setAgents(res.data || [])
    } catch (e) {
      message.error('加载Agent列表失败')
    } finally {
      setLoading(false)
    }
  }

  const columns = [
    {
      title: 'Agent ID', dataIndex: 'agentId', key: 'agentId', width: 260,
      render: id => <Text code>{id}</Text>
    },
    {
      title: '应用名称', dataIndex: 'appName', key: 'appName', width: 150
    },
    {
      title: '状态', dataIndex: 'status', key: 'status', width: 100,
      render: s => s === 'ONLINE'
        ? <Tag icon={<CheckCircleOutlined />} color="success">在线</Tag>
        : <Tag icon={<CloseCircleOutlined />} color="error">离线</Tag>
    },
    {
      title: 'Agent 版本', dataIndex: 'agentVersion', key: 'agentVersion', width: 100
    },
    {
      title: 'Java 版本', dataIndex: 'javaVersion', key: 'javaVersion', width: 100
    },
    {
      title: '宿主机 IP', dataIndex: 'hostIp', key: 'hostIp', width: 140
    },
    {
      title: '最后心跳', dataIndex: 'lastHeartbeat', key: 'lastHeartbeat', width: 170,
      render: t => t ? dayjs(t).format('MM-DD HH:mm:ss') : '-',
      sorter: (a, b) => {
        if (!a.lastHeartbeat) return 1
        if (!b.lastHeartbeat) return -1
        return dayjs(a.lastHeartbeat).unix() - dayjs(b.lastHeartbeat).unix()
      },
      defaultSortOrder: 'descend'
    },
    {
      title: '注册时间', dataIndex: 'registeredAt', key: 'registeredAt', width: 170,
      render: t => t ? dayjs(t).format('MM-DD HH:mm:ss') : '-'
    }
  ]

  const onlineCount = agents.filter(a => a.status === 'ONLINE').length

  return (
    <div>
      <Card>
        <Space style={{ marginBottom: 16, width: '100%', justifyContent: 'space-between' }}>
          <Space>
            <Tag color="success">在线: {onlineCount}</Tag>
            <Tag color="default">总数: {agents.length}</Tag>
          </Space>
          <Button icon={<ReloadOutlined />} onClick={loadAgents}>刷新</Button>
        </Space>
        <Table dataSource={agents} columns={columns} rowKey="id"
          loading={loading} pagination={false} size="middle"
          scroll={{ x: 1000 }}
          locale={{ emptyText: '暂无注册的 Agent' }} />
      </Card>
    </div>
  )
}
