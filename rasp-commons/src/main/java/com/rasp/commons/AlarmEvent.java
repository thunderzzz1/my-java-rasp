package com.rasp.commons;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * 告警事件 - RASP 检测到攻击时生成的完整事件记录
 * 
 * 包含攻击的完整上下文信息，用于告警展示、日志记录和回溯分析。
 * 设计为不可变对象，通过 Builder 模式构建。
 */
public class AlarmEvent {

    /** 全局唯一告警 ID */
    private final String alarmId;

    /** 应用名称 */
    private final String appName;

    /** Agent 标识 */
    private final String agentId;

    /** 攻击类型 */
    private final AttackType attackType;

    /** 严重程度 */
    private final Severity severity;

    /** 处理动作：BLOCK / ALERT */
    private final String action;

    /** 人类可读的告警描述 */
    private final String message;

    /** 证据信息（SQL语句、命令、文件路径等） */
    private final Map<String, Object> evidence;

    /** 请求 URI */
    private final String requestUri;

    /** 客户端 IP */
    private final String remoteAddr;

    /** 触发 Hook 的类名 */
    private final String hookClassName;

    /** 触发 Hook 的方法名 */
    private final String hookMethodName;

    /** 方法参数（脱敏后） */
    private final String hookArguments;

    /** 调用栈（截断） */
    private final String stackTrace;

    /** 告警时间戳（毫秒） */
    private final long timestamp;

    private AlarmEvent(Builder builder) {
        this.alarmId = builder.alarmId != null ? builder.alarmId : UUID.randomUUID().toString();
        this.appName = builder.appName;
        this.agentId = builder.agentId;
        this.attackType = builder.attackType;
        this.severity = builder.severity;
        this.action = builder.action;
        this.message = builder.message;
        this.evidence = builder.evidence != null ? new HashMap<>(builder.evidence) : new HashMap<>();
        this.requestUri = builder.requestUri;
        this.remoteAddr = builder.remoteAddr;
        this.hookClassName = builder.hookClassName;
        this.hookMethodName = builder.hookMethodName;
        this.hookArguments = builder.hookArguments;
        this.stackTrace = builder.stackTrace;
        this.timestamp = builder.timestamp > 0 ? builder.timestamp : System.currentTimeMillis();
    }

    // --- Getters ---

    public String getAlarmId() { return alarmId; }
    public String getAppName() { return appName; }
    public String getAgentId() { return agentId; }
    public AttackType getAttackType() { return attackType; }
    public Severity getSeverity() { return severity; }
    public String getAction() { return action; }
    public String getMessage() { return message; }
    public Map<String, Object> getEvidence() { return new HashMap<>(evidence); }
    public String getRequestUri() { return requestUri; }
    public String getRemoteAddr() { return remoteAddr; }
    public String getHookClassName() { return hookClassName; }
    public String getHookMethodName() { return hookMethodName; }
    public String getHookArguments() { return hookArguments; }
    public String getStackTrace() { return stackTrace; }
    public long getTimestamp() { return timestamp; }

    /**
     * 转换为 JSON 字符串（用于上报）
     */
    public String toJson() {
        StringBuilder sb = new StringBuilder("{");
        appendField(sb, "alarmId", alarmId);
        appendField(sb, "appName", appName);
        appendField(sb, "agentId", agentId);
        appendField(sb, "attackType", attackType != null ? attackType.name() : null);
        appendField(sb, "severity", severity != null ? severity.getLabel() : null);
        appendField(sb, "action", action);
        appendField(sb, "message", message);
        appendNonString(sb, "timestamp", timestamp);
        sb.append("\"evidence\":{");
        if (!evidence.isEmpty()) {
            boolean first = true;
            for (Map.Entry<String, Object> e : evidence.entrySet()) {
                if (!first) sb.append(",");
                appendField(sb, e.getKey(), e.getValue() != null ? e.getValue().toString() : null);
                first = false;
            }
        }
        sb.append("},");
        appendField(sb, "requestUri", requestUri);
        appendField(sb, "remoteAddr", remoteAddr);
        appendField(sb, "hookClassName", hookClassName);
        appendField(sb, "hookMethodName", hookMethodName);
        appendField(sb, "hookArguments", hookArguments);
        // 截断调用栈避免 JSON 过大
        if (stackTrace != null && stackTrace.length() > 2000) {
            appendField(sb, "stackTrace", stackTrace.substring(0, 2000) + "...[truncated]");
        } else {
            appendField(sb, "stackTrace", stackTrace);
        }
        // 移除末尾逗号
        if (sb.charAt(sb.length() - 1) == ',') {
            sb.setLength(sb.length() - 1);
        }
        sb.append("}");
        return sb.toString();
    }

    private void appendField(StringBuilder sb, String key, String value) {
        sb.append("\"").append(escape(key)).append("\":");
        if (value == null) {
            sb.append("null");
        } else {
            sb.append("\"").append(escape(value)).append("\"");
        }
        sb.append(",");
    }

    private void appendNonString(StringBuilder sb, String key, long value) {
        sb.append("\"").append(escape(key)).append("\":").append(value).append(",");
    }

    private String escape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    @Override
    public String toString() {
        return String.format("[%s] %s: %s (uri=%s, ip=%s)",
                severity.getLabel(), attackType, message, requestUri, remoteAddr);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private String alarmId;
        private String appName = "unknown";
        private String agentId = "unknown";
        private AttackType attackType = AttackType.UNKNOWN;
        private Severity severity = Severity.MEDIUM;
        private String action = "BLOCK";
        private String message;
        private Map<String, Object> evidence;
        private String requestUri;
        private String remoteAddr;
        private String hookClassName;
        private String hookMethodName;
        private String hookArguments;
        private String stackTrace;
        private long timestamp;

        public Builder alarmId(String alarmId) { this.alarmId = alarmId; return this; }
        public Builder appName(String appName) { this.appName = appName; return this; }
        public Builder agentId(String agentId) { this.agentId = agentId; return this; }
        public Builder attackType(AttackType attackType) { this.attackType = attackType; return this; }
        public Builder severity(Severity severity) { this.severity = severity; return this; }
        public Builder action(String action) { this.action = action; return this; }
        public Builder message(String message) { this.message = message; return this; }
        public Builder evidence(Map<String, Object> evidence) { this.evidence = evidence; return this; }
        public Builder addEvidence(String key, Object value) {
            if (this.evidence == null) this.evidence = new HashMap<>();
            this.evidence.put(key, value);
            return this;
        }
        public Builder requestUri(String requestUri) { this.requestUri = requestUri; return this; }
        public Builder remoteAddr(String remoteAddr) { this.remoteAddr = remoteAddr; return this; }
        public Builder hookClassName(String hookClassName) { this.hookClassName = hookClassName; return this; }
        public Builder hookMethodName(String hookMethodName) { this.hookMethodName = hookMethodName; return this; }
        public Builder hookArguments(String hookArguments) { this.hookArguments = hookArguments; return this; }
        public Builder stackTrace(String stackTrace) { this.stackTrace = stackTrace; return this; }
        public Builder timestamp(long timestamp) { this.timestamp = timestamp; return this; }
        public AlarmEvent build() { return new AlarmEvent(this); }
    }
}
