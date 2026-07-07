package com.rasp.core.context;

import com.rasp.commons.AlarmEvent;

import java.util.*;

/**
 * RASP 请求上下文
 * 
 * 存储在当前请求线程的 ThreadLocal 中，贯穿整个请求生命周期。
 * 包含 HTTP 请求的全部信息，供检测器进行参数关联分析。
 * 
 * 设计要点：
 * 1. 使用 ThreadLocal 隔离不同请求
 * 2. 在请求出口必须调用 destroy() 防止内存泄漏
 * 3. 参数使用不可变拷贝，防止并发修改
 */
public class RaspContext {

    private static final ThreadLocal<RaspContext> CONTEXT_HOLDER = new ThreadLocal<>();

    /** 全局唯一请求 ID */
    private final String requestId;

    /** 请求创建时间（纳秒，用于性能统计） */
    private final long createTimeNanos;

    /** 请求 URI */
    private String requestUri;

    /** HTTP 方法 */
    private String httpMethod;

    /** 客户端 IP */
    private String remoteAddr;

    /** 请求参数：key → values[] */
    private volatile Map<String, String[]> parameters;

    /** 请求头 */
    private Map<String, String> headers;

    /** Cookie */
    private Map<String, String> cookies;

    /** 当前请求中触发的所有 Hook 事件 */
    private final List<HookEvent> hookEvents;

    /** 当前请求中检测到的攻击事件 */
    private final List<AlarmEvent> alarms;

    /** 是否开启检测（可用于降级开关） */
    private volatile boolean detectionEnabled = true;

    /** 当前请求的安全上下文标记（白名单、内部调用等） */
    private final Set<String> securityTags;

    /**
     * 私有构造，通过工厂方法创建
     */
    private RaspContext() {
        this.requestId = UUID.randomUUID().toString().replace("-", "");
        this.createTimeNanos = System.nanoTime();
        this.hookEvents = new ArrayList<>(4);
        this.alarms = new ArrayList<>(2);
        this.securityTags = new HashSet<>(2);
    }

    // ===== 工厂方法和生命周期 =====

    /**
     * 创建并绑定上下文到当前线程
     */
    public static RaspContext create() {
        RaspContext ctx = new RaspContext();
        CONTEXT_HOLDER.set(ctx);
        return ctx;
    }

    /**
     * 获取当前线程的上下文，可能为 null（非请求线程）
     */
    public static RaspContext get() {
        return CONTEXT_HOLDER.get();
    }

    /**
     * 清理并解绑当前线程的上下文
     * 必须在 try-finally 中调用，确保异常情况下也能清理
     */
    public static void destroy() {
        RaspContext ctx = CONTEXT_HOLDER.get();
        if (ctx != null) {
            ctx.cleanup();
            CONTEXT_HOLDER.remove();
        }
    }

    /**
     * 清理内部资源
     */
    private void cleanup() {
        this.parameters = null;
        this.headers = null;
        this.cookies = null;
        this.hookEvents.clear();
        this.alarms.clear();
        this.securityTags.clear();
    }

    // ===== 参数关联分析 =====

    /**
     * 核心检测方法：检查 API 参数是否包含 HTTP 请求参数值
     * 
     * 这是 RASP 对抗 0day 的关键能力：
     * 不需要知道漏洞的精确 payload，只要发现"用户输入直接出现在了敏感 API 调用中"就触发
     *
     * @param apiArg 敏感 API 调用的参数（如 SQL 语句、命令字符串、文件路径）
     * @return 如果包含请求参数则返回 true
     */
    public boolean isParamTainted(String apiArg) {
        if (apiArg == null || apiArg.isEmpty()) {
            return false;
        }
        Map<String, String[]> params = this.parameters;
        if (params == null || params.isEmpty()) {
            return false;
        }

        for (Map.Entry<String, String[]> entry : params.entrySet()) {
            for (String value : entry.getValue()) {
                if (value != null && value.length() > 2 && apiArg.contains(value)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * 检查参数值是否完整等于输入
     */
    public boolean isParamExactMatch(String apiArg) {
        if (apiArg == null) return false;
        Map<String, String[]> params = this.parameters;
        if (params == null) return false;

        for (String[] values : params.values()) {
            for (String value : values) {
                if (apiArg.equals(value)) {
                    return true;
                }
            }
        }
        return false;
    }

    // ===== Hook 事件管理 =====

    public void addHookEvent(HookEvent event) {
        if (event != null && hookEvents.size() < 100) { // 防止内存无限增长
            hookEvents.add(event);
        }
    }

    public List<HookEvent> getHookEvents() {
        return Collections.unmodifiableList(hookEvents);
    }

    // ===== 告警管理 =====

    public void addAlarm(AlarmEvent alarm) {
        if (alarm != null) {
            alarms.add(alarm);
        }
    }

    public List<AlarmEvent> getAlarms() {
        return Collections.unmodifiableList(alarms);
    }

    public boolean hasAlarms() {
        return !alarms.isEmpty();
    }

    // ===== Getters and Setters =====

    public String getRequestId() { return requestId; }
    public long getCreateTimeNanos() { return createTimeNanos; }

    public String getRequestUri() { return requestUri; }
    public void setRequestUri(String requestUri) { this.requestUri = requestUri; }

    public String getHttpMethod() { return httpMethod; }
    public void setHttpMethod(String httpMethod) { this.httpMethod = httpMethod; }

    public String getRemoteAddr() { return remoteAddr; }
    public void setRemoteAddr(String remoteAddr) { this.remoteAddr = remoteAddr; }

    public Map<String, String[]> getParameters() {
        return parameters;
    }

    public void setParameters(Map<String, String[]> parameters) {
        // 防御性拷贝
        if (parameters != null) {
            Map<String, String[]> copy = new HashMap<>(parameters.size());
            for (Map.Entry<String, String[]> entry : parameters.entrySet()) {
                String[] values = entry.getValue();
                copy.put(entry.getKey(), values != null ? values.clone() : new String[0]);
            }
            this.parameters = Collections.unmodifiableMap(copy);
        }
    }

    public String getHeader(String name) {
        return headers != null ? headers.get(name.toLowerCase()) : null;
    }

    public void setHeaders(Map<String, String> headers) {
        if (headers != null) {
            this.headers = new HashMap<>(headers.size());
            for (Map.Entry<String, String> e : headers.entrySet()) {
                this.headers.put(e.getKey().toLowerCase(), e.getValue());
            }
        }
    }

    public void setCookies(Map<String, String> cookies) {
        this.cookies = cookies != null ? new HashMap<>(cookies) : null;
    }

    public boolean isDetectionEnabled() { return detectionEnabled; }
    public void setDetectionEnabled(boolean detectionEnabled) { this.detectionEnabled = detectionEnabled; }

    public void addSecurityTag(String tag) { this.securityTags.add(tag); }
    public boolean hasSecurityTag(String tag) { return securityTags.contains(tag); }

    @Override
    public String toString() {
        return "RaspContext{id=" + requestId + ", uri=" + requestUri
                + ", method=" + httpMethod + ", ip=" + remoteAddr + "}";
    }
}
