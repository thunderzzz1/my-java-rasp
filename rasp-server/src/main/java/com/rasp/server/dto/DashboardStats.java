package com.rasp.server.dto;

import java.util.Map;

/**
 * 攻击大盘统计 DTO
 */
public class DashboardStats {

    /** 总攻击数 */
    private long totalAttacks;

    /** 已阻断数 */
    private long blockedCount;

    /** 今日攻击数 */
    private long todayAttacks;

    /** 各攻击类型统计 */
    private Map<String, Long> attackTypeCounts;

    /** 各严重级别统计 */
    private Map<String, Long> severityCounts;

    /** 在线 Agent 数 */
    private long onlineAgents;

    public DashboardStats() {}

    public long getTotalAttacks() { return totalAttacks; }
    public void setTotalAttacks(long totalAttacks) { this.totalAttacks = totalAttacks; }

    public long getBlockedCount() { return blockedCount; }
    public void setBlockedCount(long blockedCount) { this.blockedCount = blockedCount; }

    public long getTodayAttacks() { return todayAttacks; }
    public void setTodayAttacks(long todayAttacks) { this.todayAttacks = todayAttacks; }

    public Map<String, Long> getAttackTypeCounts() { return attackTypeCounts; }
    public void setAttackTypeCounts(Map<String, Long> attackTypeCounts) { this.attackTypeCounts = attackTypeCounts; }

    public Map<String, Long> getSeverityCounts() { return severityCounts; }
    public void setSeverityCounts(Map<String, Long> severityCounts) { this.severityCounts = severityCounts; }

    public long getOnlineAgents() { return onlineAgents; }
    public void setOnlineAgents(long onlineAgents) { this.onlineAgents = onlineAgents; }
}
