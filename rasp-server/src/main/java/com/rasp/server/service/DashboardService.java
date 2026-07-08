package com.rasp.server.service;

import com.rasp.server.dto.AttackTrend;
import com.rasp.server.dto.DashboardStats;
import com.rasp.server.repository.AlarmRecordRepository;
import com.rasp.server.repository.AgentInfoRepository;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.*;
import java.util.stream.Collectors;

/**
 * 大盘统计服务
 */
@Service
public class DashboardService {

    private final AlarmRecordRepository alarmRepo;
    private final AgentInfoRepository agentRepo;

    public DashboardService(AlarmRecordRepository alarmRepo, AgentInfoRepository agentRepo) {
        this.alarmRepo = alarmRepo;
        this.agentRepo = agentRepo;
    }

    /**
     * 获取攻击大盘统计数据
     */
    public DashboardStats getStats() {
        DashboardStats stats = new DashboardStats();

        // 总攻击数
        stats.setTotalAttacks(alarmRepo.count());

        // 总阻断数 (估算 - 实际需要按 blocked=true 查询)
        // 简化: 假设所有 HIGH/CRITICAL 告警都被阻断
        long totalBlocked = alarmRepo.findAll().stream()
            .filter(a -> a.isBlocked()).count();
        stats.setBlockedCount(totalBlocked);

        // 今日攻击数
        LocalDateTime todayStart = LocalDate.now().atStartOfDay();
        LocalDateTime todayEnd = LocalDate.now().atTime(LocalTime.MAX);
        stats.setTodayAttacks(alarmRepo.countByTimestampBetween(todayStart, todayEnd));

        // 攻击类型分布
        Map<String, Long> typeCounts = new LinkedHashMap<>();
        List<Object[]> typeResults = alarmRepo.countByAttackType();
        for (Object[] row : typeResults) {
            typeCounts.put((String) row[0], (Long) row[1]);
        }
        stats.setAttackTypeCounts(typeCounts);

        // 严重级别分布
        Map<String, Long> severityCounts = new LinkedHashMap<>();
        List<Object[]> severityResults = alarmRepo.countBySeverity();
        for (Object[] row : severityResults) {
            severityCounts.put((String) row[0], (Long) row[1]);
        }
        stats.setSeverityCounts(severityCounts);

        // 在线 Agent 数
        stats.setOnlineAgents(agentRepo.countByStatus("ONLINE"));

        return stats;
    }

    /**
     * 获取最近24小时攻击趋势
     */
    public AttackTrend getTrend() {
        AttackTrend trend = new AttackTrend();
        LocalDateTime since = LocalDateTime.now().minusHours(24);

        List<Object[]> results = alarmRepo.countByHourSince(since);

        List<Map<String, Object>> trendData = new ArrayList<>();
        String peakHour = "";
        long peakCount = 0;

        for (Object[] row : results) {
            Map<String, Object> point = new LinkedHashMap<>();
            String hour = (String) row[0];
            long count = (Long) row[1];
            point.put("hour", hour);
            point.put("count", count);
            trendData.add(point);

            if (count > peakCount) {
                peakCount = count;
                peakHour = hour;
            }
        }

        trend.setTrendData(trendData);
        trend.setPeakHour(peakHour);
        trend.setPeakCount(peakCount);

        return trend;
    }
}
