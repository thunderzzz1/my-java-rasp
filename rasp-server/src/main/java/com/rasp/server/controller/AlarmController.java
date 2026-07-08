package com.rasp.server.controller;

import com.rasp.server.model.AlarmRecord;
import com.rasp.server.service.AlarmService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.*;

/**
 * 告警管理 REST API
 */
@RestController
@RequestMapping("/api/alarms")
public class AlarmController {

    private final AlarmService alarmService;

    public AlarmController(AlarmService alarmService) {
        this.alarmService = alarmService;
    }

    /**
     * 分页查询告警列表
     * GET /api/alarms?page=0&size=20
     */
    @GetMapping
    public ResponseEntity<Map<String, Object>> listAlarms(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        List<AlarmRecord> alarms = alarmService.listAlarms(page, size);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", true);
        result.put("data", alarms);
        result.put("total", alarmService.count());
        result.put("page", page);
        result.put("size", size);
        return ResponseEntity.ok(result);
    }

    /**
     * 按 ID 查询单个告警
     */
    @GetMapping("/{id}")
    public ResponseEntity<Map<String, Object>> getAlarm(@PathVariable Long id) {
        Optional<AlarmRecord> alarm = alarmService.getById(id);
        Map<String, Object> result = new LinkedHashMap<>();
        if (alarm.isPresent()) {
            result.put("success", true);
            result.put("data", alarm.get());
        } else {
            result.put("success", false);
            result.put("error", "Alarm not found");
        }
        return ResponseEntity.ok(result);
    }

    /**
     * 查询最近的告警 (最新100条)
     */
    @GetMapping("/recent")
    public ResponseEntity<Map<String, Object>> getRecent() {
        List<AlarmRecord> alarms = alarmService.getRecent();
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", true);
        result.put("data", alarms);
        result.put("count", alarms.size());
        return ResponseEntity.ok(result);
    }

    /**
     * 按攻击类型筛选
     * GET /api/alarms/filter/type?type=SQL_INJECTION
     */
    @GetMapping("/filter/type")
    public ResponseEntity<Map<String, Object>> filterByType(@RequestParam String type) {
        List<AlarmRecord> alarms = alarmService.findByAttackType(type);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", true);
        result.put("data", alarms);
        result.put("count", alarms.size());
        return ResponseEntity.ok(result);
    }

    /**
     * 按严重级别筛选
     */
    @GetMapping("/filter/severity")
    public ResponseEntity<Map<String, Object>> filterBySeverity(@RequestParam String severity) {
        List<AlarmRecord> alarms = alarmService.findBySeverity(severity);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", true);
        result.put("data", alarms);
        result.put("count", alarms.size());
        return ResponseEntity.ok(result);
    }

    /**
     * 按时间范围筛选
     * GET /api/alarms/filter/time?start=2026-07-01T00:00:00&end=2026-07-08T23:59:59
     */
    @GetMapping("/filter/time")
    public ResponseEntity<Map<String, Object>> filterByTime(
            @RequestParam String start,
            @RequestParam String end) {
        LocalDateTime startTime = LocalDateTime.parse(start);
        LocalDateTime endTime = LocalDateTime.parse(end);
        List<AlarmRecord> alarms = alarmService.findByTimeRange(startTime, endTime);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", true);
        result.put("data", alarms);
        result.put("count", alarms.size());
        return ResponseEntity.ok(result);
    }

    /**
     * 删除告警
     */
    @DeleteMapping("/{id}")
    public ResponseEntity<Map<String, Object>> deleteAlarm(@PathVariable Long id) {
        alarmService.deleteById(id);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", true);
        result.put("message", "Alarm deleted");
        return ResponseEntity.ok(result);
    }

    /**
     * 批量删除
     */
    @PostMapping("/batch-delete")
    public ResponseEntity<Map<String, Object>> batchDelete(@RequestBody List<Long> ids) {
        alarmService.deleteBatch(ids);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", true);
        result.put("deleted", ids.size());
        return ResponseEntity.ok(result);
    }
}
