import React, { useEffect, useState } from 'react'
import { Card, Table, Tag, Space, Button, Popconfirm, Select, DatePicker, message, Typography, Modal } from 'antd'
import { DeleteOutlined, ReloadOutlined, SearchOutlined, EyeOutlined } from '@ant-design/icons'
import { fetchAlarms, fetchAlarmsByType, fetchAlarmsBySeverity, fetchAlarmsByTime, deleteAlarm } from '../api'
import dayjs from 'dayjs'

const { Text, Paragraph } = Typography
const { RangePicker } = DatePicker

const severityColors = { HIGH: 'red', CRITICAL: '#ff4d4f', MEDIUM: 'orange', LOW: 'blue' }
const typeNames = {
  SQL_INJECTION: 'SQL注入', COMMAND_EXEC: '命令执行', DESERIALIZATION: '反序列化',
  FILE_OP: '文件操作', SSRF: 'SSRF', JNDI_INJECTION: 'JNDI注入'
}

export default function Alarms() {
  const [alarms, setAlarms] = useState([])
  const [loading, setLoading] = useState(true)
  const [pagination, setPagination] = useState({ current: 1, pageSize: 20, total: 0 })
  const [filters, setFilters] = useState({ type: '', severity: '', timeRange: null })
  const [detailVisible, setDetailVisible] = useState(false)
  const [selectedAlarm, setSelectedAlarm] = useState(null)

  useEffect(() => { loadAlarms() }, [pagination.current])

  async function loadAlarms() {
    setLoading(true)
    try {
      let res
      if (filters.type) {
        res = await fetchAlarmsByType(filters.type)
      } else if (filters.severity) {
        res = await fetchAlarmsBySeverity(filters.severity)
      } else if (filters.timeRange) {
        const [start, end] = filters.timeRange
        res = await fetchAlarmsByTime(
          start.format('YYYY-MM-DDTHH:mm:ss'),
          end.format('YYYY-MM-DDTHH:mm:ss')
        )
      } else {
        res = await fetchAlarms(pagination.current - 1, pagination.pageSize)
      }
      setAlarms(res.data || [])
      if (res.total) setPagination(prev => ({ ...prev, total: res.total }))
    } catch (e) {
      message.error('加载告警失败')
    } finally {
      setLoading(false)
    }
  }

  async function handleDelete(id) {
    try {
      await deleteAlarm(id)
      message.success('已删除')
      loadAlarms()
    } catch (e) {
      message.error('删除失败')
    }
  }

  function showDetail(record) {
    setSelectedAlarm(record)
    setDetailVisible(true)
  }

  function resetFilters() {
    setFilters({ type: '', severity: '', timeRange: null })
    setPagination({ current: 1, pageSize: 20, total: 0 })
    setTimeout(loadAlarms, 0)
  }

  const columns = [
    {
      title: '时间', dataIndex: 'timestamp', width: 170, key: 'timestamp',
      render: t => t && dayjs(t).format('MM-DD HH:mm:ss'),
      sorter: (a, b) => dayjs(a.timestamp).unix() - dayjs(b.timestamp).unix(),
      defaultSortOrder: 'descend'
    },
    {
      title: '攻击类型', dataIndex: 'attackType', width: 120, key: 'attackType',
      render: t => <Tag color="blue">{typeNames[t] || t}</Tag>
    },
    {
      title: '严重级别', dataIndex: 'severity', width: 100, key: 'severity',
      render: s => <Tag color={severityColors[s]}>{s}</Tag>
    },
    {
      title: '描述', dataIndex: 'title', key: 'title', ellipsis: true,
      render: (t, r) => <Space><Text ellipsis style={{ maxWidth: 300 }}>{t}</Text>
        {r.blocked && <Tag color="green">已阻断</Tag>}
      </Space>
    },
    {
      title: '来源IP', dataIndex: 'sourceIp', width: 140, key: 'sourceIp',
      render: ip => ip || '-'
    },
    {
      title: '请求路径', dataIndex: 'httpPath', width: 160, key: 'httpPath', ellipsis: true
    },
    {
      title: '操作', key: 'action', width: 120,
      render: (_, record) => (
        <Space>
          <Button type="link" size="small" icon={<EyeOutlined />}
            onClick={() => showDetail(record)}>详情</Button>
          <Popconfirm title="确认删除？" onConfirm={() => handleDelete(record.id)}>
            <Button type="link" danger size="small" icon={<DeleteOutlined />} />
          </Popconfirm>
        </Space>
      )
    }
  ]

  return (
    <div>
      <Card>
        {/* 筛选栏 */}
        <Space style={{ marginBottom: 16 }} wrap>
          <Select placeholder="攻击类型" allowClear style={{ width: 140 }}
            value={filters.type || undefined}
            onChange={v => { setFilters(prev => ({ ...prev, type: v || '' })); setPagination(prev => ({ ...prev, current: 1 })) }}
            options={Object.entries(typeNames).map(([k, v]) => ({ value: k, label: v }))} />
          <Select placeholder="严重级别" allowClear style={{ width: 120 }}
            value={filters.severity || undefined}
            onChange={v => { setFilters(prev => ({ ...prev, severity: v || '' })); setPagination(prev => ({ ...prev, current: 1 })) }}
            options={['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(s => ({ value: s, label: s }))} />
          <RangePicker showTime format="YYYY-MM-DD HH:mm:ss"
            onChange={dates => setFilters(prev => ({ ...prev, timeRange: dates ? [dates[0], dates[1]] : null }))} />
          <Button type="primary" icon={<SearchOutlined />} onClick={loadAlarms}>查询</Button>
          <Button icon={<ReloadOutlined />} onClick={resetFilters}>重置</Button>
        </Space>

        {/* 表格 */}
        <Table dataSource={alarms} columns={columns} rowKey="id"
          loading={loading} pagination={pagination}
          onChange={pag => setPagination(pag)}
          size="middle" scroll={{ x: 1100 }} />
      </Card>

      {/* 详情弹窗 */}
      <Modal title="告警详情" open={detailVisible} onCancel={() => setDetailVisible(false)}
        footer={null} width={700}>
        {selectedAlarm && (
          <Space direction="vertical" style={{ width: '100%' }} size="middle">
            <div><Text strong>攻击类型：</Text><Tag color="blue">{typeNames[selectedAlarm.attackType] || selectedAlarm.attackType}</Tag></div>
            <div><Text strong>严重级别：</Text><Tag color={severityColors[selectedAlarm.severity]}>{selectedAlarm.severity}</Tag></div>
            <div><Text strong>是否阻断：</Text>{selectedAlarm.blocked ? <Tag color="green">已阻断</Tag> : <Tag color="orange">未阻断</Tag>}</div>
            <div><Text strong>时间：</Text>{selectedAlarm.timestamp}</div>
            <div><Text strong>来源IP：</Text>{selectedAlarm.sourceIp || '-'}</div>
            <div><Text strong>请求路径：</Text><Text code>{selectedAlarm.httpPath || '-'}</Text></div>
            <div><Text strong>描述：</Text><Paragraph>{selectedAlarm.title}</Paragraph></div>
            {selectedAlarm.payload && <div><Text strong>攻击载荷：</Text><Paragraph code style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>{selectedAlarm.payload}</Paragraph></div>}
            {selectedAlarm.stackTrace && <div><Text strong>堆栈：</Text><Paragraph code style={{ whiteSpace: 'pre-wrap', fontSize: 12, maxHeight: 200, overflow: 'auto' }}>{selectedAlarm.stackTrace}</Paragraph></div>}
          </Space>
        )}
      </Modal>
    </div>
  )
}
