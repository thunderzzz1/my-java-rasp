package com.rasp.server.model;

import com.fasterxml.jackson.annotation.JsonFormat;
import javax.persistence.*;
import java.time.LocalDateTime;

/**
 * 攻击告警记录 - 持久化实体
 * 对应 rasp-commons 中的 AlarmEvent，增加数据库字段
 */
@Entity
@Table(name = "rasp_alarms", indexes = {
    @Index(name = "idx_attack_type", columnList = "attack_type"),
    @Index(name = "idx_severity", columnList = "severity"),
    @Index(name = "idx_timestamp", columnList = "timestamp"),
    @Index(name = "idx_app_name", columnList = "app_name"),
    @Index(name = "idx_blocked", columnList = "blocked")
})
public class AlarmRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** 攻击类型: SQL_INJECTION / COMMAND_EXEC / DESERIALIZATION / FILE_OP / SSRF / JNDI_INJECTION */
    @Column(name = "attack_type", nullable = false, length = 50)
    private String attackType;

    /** 严重级别: LOW / MEDIUM / HIGH / CRITICAL */
    @Column(nullable = false, length = 20)
    private String severity;

    /** 告警标题/描述 */
    @Column(nullable = false, length = 500)
    private String title;

    /** 详细描述 */
    @Column(columnDefinition = "CLOB")
    private String description;

    /** 是否已阻断 */
    @Column(nullable = false)
    private boolean blocked;

    /** 攻击来源 IP */
    @Column(name = "source_ip", length = 45)
    private String sourceIp;

    /** 目标应用名称 */
    @Column(name = "app_name", length = 100)
    private String appName;

    /** HTTP 请求方法 */
    @Column(name = "http_method", length = 10)
    private String httpMethod;

    /** HTTP 请求路径 */
    @Column(name = "http_path", length = 500)
    private String httpPath;

    /** 攻击载荷 (截断存储) */
    @Column(columnDefinition = "CLOB")
    private String payload;

    /** 堆栈跟踪 */
    @Column(name = "stack_trace", columnDefinition = "CLOB")
    private String stackTrace;

    /** 额外信息 (JSON格式) */
    @Column(columnDefinition = "CLOB")
    private String extraInfo;

    /** 事件时间戳 */
    @Column(nullable = false)
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime timestamp;

    /** 记录创建时间 */
    @Column(name = "created_at", nullable = false, updatable = false)
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        if (createdAt == null) {
            createdAt = LocalDateTime.now();
        }
        if (timestamp == null) {
            timestamp = LocalDateTime.now();
        }
    }

    // ==================== Getters & Setters ====================

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getAttackType() { return attackType; }
    public void setAttackType(String attackType) { this.attackType = attackType; }

    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }

    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public boolean isBlocked() { return blocked; }
    public void setBlocked(boolean blocked) { this.blocked = blocked; }

    public String getSourceIp() { return sourceIp; }
    public void setSourceIp(String sourceIp) { this.sourceIp = sourceIp; }

    public String getAppName() { return appName; }
    public void setAppName(String appName) { this.appName = appName; }

    public String getHttpMethod() { return httpMethod; }
    public void setHttpMethod(String httpMethod) { this.httpMethod = httpMethod; }

    public String getHttpPath() { return httpPath; }
    public void setHttpPath(String httpPath) { this.httpPath = httpPath; }

    public String getPayload() { return payload; }
    public void setPayload(String payload) { this.payload = payload; }

    public String getStackTrace() { return stackTrace; }
    public void setStackTrace(String stackTrace) { this.stackTrace = stackTrace; }

    public String getExtraInfo() { return extraInfo; }
    public void setExtraInfo(String extraInfo) { this.extraInfo = extraInfo; }

    public LocalDateTime getTimestamp() { return timestamp; }
    public void setTimestamp(LocalDateTime timestamp) { this.timestamp = timestamp; }

    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
}
