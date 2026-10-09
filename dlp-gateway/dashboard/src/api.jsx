import axios from 'axios'

const BASE = '/api'

function authHeader() {
  const token = localStorage.getItem('dlp_token')
  return token ? { Authorization: `Bearer ${token}` } : {}
}

export async function login(username, password) {
  const resp = await axios.post(`${BASE}/auth/login`, { username, password })
  return resp
}

export async function getStats() {
  return axios.get(`${BASE}/admin/stats`, { headers: authHeader() })
}

export async function getEvents(limit = 100, decision = '') {
  const params = { limit }
  if (decision) params.decision = decision
  return axios.get(`${BASE}/admin/events`, { headers: authHeader(), params })
}

export async function getUsers(limit = 100) {
  return axios.get(`${BASE}/admin/users`, { headers: authHeader(), params: { limit } })
}

export async function getAlerts(limit = 100, dismissed = false) {
  return axios.get(`${BASE}/admin/alerts`, {
    headers: authHeader(),
    params: { limit, dismissed },
  })
}

export async function dismissAlert(alertId) {
  return axios.post(`${BASE}/admin/alerts/${alertId}/dismiss`, {}, { headers: authHeader() })
}
