package com.rasp.commons;

/**
 * 安全事件严重程度
 */
public enum Severity {
    /** 高危 - 可能导致服务器被完全控制（RCE、反序列化、SQL注入写文件） */
    HIGH("HIGH", 3),
    
    /** 中危 - 可能导致数据泄露或有限控制（SSRF、路径遍历读文件、JNDI） */
    MEDIUM("MEDIUM", 2),
    
    /** 低危 - 信息泄露或低影响攻击（XSS、敏感信息泄露） */
    LOW("LOW", 1),
    
    /** 信息 - 仅用于记录，不需要告警 */
    INFO("INFO", 0);

    private final String label;
    private final int level;

    Severity(String label, int level) {
        this.label = label;
        this.level = level;
    }

    public String getLabel() { return label; }
    public int getLevel() { return level; }
}
