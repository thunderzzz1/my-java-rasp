package com.rasp.server.controller;

import com.rasp.server.model.AgentInfo;
import com.rasp.server.repository.AgentInfoRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.*;

/**
 * Agent 管理 REST API
 */
@RestController
@RequestMapping("/api/agents")
public class AgentController {

    private final AgentInfoRepository agentRepo;

    public AgentController(AgentInfoRepository agentRepo) {
        this.agentRepo = agentRepo;
    }

    /**
     * Agent 注册 / 心跳
     * POST /api/agents/heartbeat
     */
    @PostMapping("/heartbeat")
    public ResponseEntity<Map<String, Object>> heartbeat(@RequestBody Map<String, String> body) {
        String agentId = body.get("agentId");
        Map<String, Object> result = new LinkedHashMap<>();

        Optional<AgentInfo> existing = agentRepo.findByAgentId(agentId);
        AgentInfo agent;
        if (existing.isPresent()) {
            // 更新心跳
            agent = existing.get();
            agent.setStatus("ONLINE");
            agent.setLastHeartbeat(LocalDateTime.now());
            agent.setHostIp(body.getOrDefault("hostIp", agent.getHostIp()));
        } else {
            // 新注册
            agent = new AgentInfo();
            agent.setAgentId(agentId);
            agent.setAppName(body.getOrDefault("appName", "unknown"));
            agent.setHostIp(body.getOrDefault("hostIp", "unknown"));
            agent.setJavaVersion(body.getOrDefault("javaVersion", "unknown"));
            agent.setAgentVersion(body.getOrDefault("agentVersion", "1.0.0"));
            agent.setStatus("ONLINE");
            agent.setLastHeartbeat(LocalDateTime.now());
        }
        agentRepo.save(agent);

        result.put("success", true);
        result.put("agentId", agentId);
        result.put("status", "ONLINE");
        return ResponseEntity.ok(result);
    }

    /**
     * 查询所有 Agent
     * GET /api/agents
     */
    @GetMapping
    public ResponseEntity<Map<String, Object>> listAgents() {
        List<AgentInfo> agents = agentRepo.findAll();
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", true);
        result.put("data", agents);
        result.put("total", agents.size());
        result.put("online", agentRepo.countByStatus("ONLINE"));
        return ResponseEntity.ok(result);
    }

    /**
     * 查询指定 Agent
     */
    @GetMapping("/{agentId}")
    public ResponseEntity<Map<String, Object>> getAgent(@PathVariable String agentId) {
        Optional<AgentInfo> agent = agentRepo.findByAgentId(agentId);
        Map<String, Object> result = new LinkedHashMap<>();
        if (agent.isPresent()) {
            result.put("success", true);
            result.put("data", agent.get());
        } else {
            result.put("success", false);
            result.put("error", "Agent not found: " + agentId);
        }
        return ResponseEntity.ok(result);
    }

    /**
     * Agent 离线通知
     */
    @PostMapping("/{agentId}/offline")
    public ResponseEntity<Map<String, Object>> markOffline(@PathVariable String agentId) {
        Optional<AgentInfo> existing = agentRepo.findByAgentId(agentId);
        Map<String, Object> result = new LinkedHashMap<>();
        if (existing.isPresent()) {
            AgentInfo agent = existing.get();
            agent.setStatus("OFFLINE");
            agentRepo.save(agent);
            result.put("success", true);
            result.put("agentId", agentId);
            result.put("status", "OFFLINE");
        } else {
            result.put("success", false);
            result.put("error", "Agent not found");
        }
        return ResponseEntity.ok(result);
    }
}
