package com.rasp.server.controller;

import com.rasp.server.dto.AttackTrend;
import com.rasp.server.dto.DashboardStats;
import com.rasp.server.service.DashboardService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.*;

/**
 * 攻击大盘 REST API
 */
@RestController
@RequestMapping("/api/dashboard")
public class DashboardController {

    private final DashboardService dashboardService;

    public DashboardController(DashboardService dashboardService) {
        this.dashboardService = dashboardService;
    }

    /**
     * 获取攻击大盘统计
     * GET /api/dashboard/stats
     */
    @GetMapping("/stats")
    public ResponseEntity<Map<String, Object>> getStats() {
        DashboardStats stats = dashboardService.getStats();
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", true);
        result.put("data", stats);
        return ResponseEntity.ok(result);
    }

    /**
     * 获取 24 小时攻击趋势
     * GET /api/dashboard/trend
     */
    @GetMapping("/trend")
    public ResponseEntity<Map<String, Object>> getTrend() {
        AttackTrend trend = dashboardService.getTrend();
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", true);
        result.put("data", trend);
        return ResponseEntity.ok(result);
    }

    /**
     * 获取汇总概览 (stats + trend + top)
     * GET /api/dashboard/overview
     */
    @GetMapping("/overview")
    public ResponseEntity<Map<String, Object>> getOverview() {
        DashboardStats stats = dashboardService.getStats();
        AttackTrend trend = dashboardService.getTrend();

        Map<String, Object> overview = new LinkedHashMap<>();
        overview.put("stats", stats);
        overview.put("trend", trend);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", true);
        result.put("data", overview);
        return ResponseEntity.ok(result);
    }
}
