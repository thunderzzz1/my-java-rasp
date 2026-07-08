package com.rasp.server.model;

import com.fasterxml.jackson.annotation.JsonFormat;
import javax.persistence.*;
import java.time.LocalDateTime;

/**
 * Agent 注册信息实体
 * 记录每次 Agent 连接/心跳的状态信息
 */
@Entity
@Table(name = "rasp_agents", indexes = {
    @Index(name = "idx_agent_status", columnList = "status"),
    @Index(name = "idx_last_heartbeat", columnList = "last_heartbeat")
})
public class AgentInfo {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** Agent 唯一标识 */
    @Column(name = "agent_id", nullable = false, unique = true, length = 64)
    private String agentId;

    /** 保护的应用名称 */
    @Column(name = "app_name", nullable = false, length = 100)
    private String appName;

    /** 宿主机 IP */
    @Column(name = "host_ip", length = 45)
    private String hostIp;

    /** JVM 版本 */
    @Column(name = "java_version", length = 50)
    private String javaVersion;

    /** Agent 版本号 */
    @Column(name = "agent_version", length = 20)
    private String agentVersion;

    /** 状态: ONLINE / OFFLINE / ERROR */
    @Column(nullable = false, length = 20)
    private String status;

    /** 最后心跳时间 */
    @Column(name = "last_heartbeat")
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime lastHeartbeat;

    /** 首次注册时间 */
    @Column(name = "registered_at", updatable = false)
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime registeredAt;

    @PrePersist
    protected void onCreate() {
        if (registeredAt == null) {
            registeredAt = LocalDateTime.now();
        }
        if (status == null) {
            status = "ONLINE";
        }
    }

    // ==================== Getters & Setters ====================

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getAgentId() { return agentId; }
    public void setAgentId(String agentId) { this.agentId = agentId; }

    public String getAppName() { return appName; }
    public void setAppName(String appName) { this.appName = appName; }

    public String getHostIp() { return hostIp; }
    public void setHostIp(String hostIp) { this.hostIp = hostIp; }

    public String getJavaVersion() { return javaVersion; }
    public void setJavaVersion(String javaVersion) { this.javaVersion = javaVersion; }

    public String getAgentVersion() { return agentVersion; }
    public void setAgentVersion(String agentVersion) { this.agentVersion = agentVersion; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public LocalDateTime getLastHeartbeat() { return lastHeartbeat; }
    public void setLastHeartbeat(LocalDateTime lastHeartbeat) { this.lastHeartbeat = lastHeartbeat; }

    public LocalDateTime getRegisteredAt() { return registeredAt; }
    public void setRegisteredAt(LocalDateTime registeredAt) { this.registeredAt = registeredAt; }
}
