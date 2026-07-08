package com.rasp.server.dto;

import java.util.List;
import java.util.Map;

/**
 * 攻击趋势 DTO
 */
public class AttackTrend {

    /** 趋势数据: [{hour: "2026-07-09 14", count: 25}, ...] */
    private List<Map<String, Object>> trendData;

    /** 峰值小时 */
    private String peakHour;

    /** 峰值攻击数 */
    private long peakCount;

    public AttackTrend() {}

    public List<Map<String, Object>> getTrendData() { return trendData; }
    public void setTrendData(List<Map<String, Object>> trendData) { this.trendData = trendData; }

    public String getPeakHour() { return peakHour; }
    public void setPeakHour(String peakHour) { this.peakHour = peakHour; }

    public long getPeakCount() { return peakCount; }
    public void setPeakCount(long peakCount) { this.peakCount = peakCount; }
}
