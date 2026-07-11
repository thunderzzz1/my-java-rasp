import axios from 'axios'

const api = axios.create({
  baseURL: '/api',
  timeout: 10000,
  headers: { 'Content-Type': 'application/json' }
})

// 响应拦截器
api.interceptors.response.use(
  response => response.data,
  error => {
    console.error('[RASP API]', error.message)
    return Promise.reject(error)
  }
)

// ==================== 大盘统计 ====================

/** 获取攻击大盘统计 */
export function fetchDashboardStats() {
  return api.get('/dashboard/stats')
}

/** 获取24小时攻击趋势 */
export function fetchAttackTrend() {
  return api.get('/dashboard/trend')
}

/** 获取大盘概览 */
export function fetchOverview() {
  return api.get('/dashboard/overview')
}

// ==================== 告警管理 ====================

/** 分页查询告警 */
export function fetchAlarms(page = 0, size = 20) {
  return api.get('/alarms', { params: { page, size } })
}

/** 获取最近告警 */
export function fetchRecentAlarms() {
  return api.get('/alarms/recent')
}

/** 按攻击类型筛选 */
export function fetchAlarmsByType(type) {
  return api.get('/alarms/filter/type', { params: { type } })
}

/** 按严重级别筛选 */
export function fetchAlarmsBySeverity(severity) {
  return api.get('/alarms/filter/severity', { params: { severity } })
}

/** 按时间范围筛选 */
export function fetchAlarmsByTime(start, end) {
  return api.get('/alarms/filter/time', { params: { start, end } })
}

/** 删除告警 */
export function deleteAlarm(id) {
  return api.delete(`/alarms/${id}`)
}

/** 批量删除 */
export function batchDeleteAlarms(ids) {
  return api.post('/alarms/batch-delete', ids)
}

// ==================== Agent 管理 ====================

/** 查询所有 Agent */
export function fetchAgents() {
  return api.get('/agents')
}

/** 查询单个 Agent */
export function fetchAgent(agentId) {
  return api.get(`/agents/${agentId}`)
}
