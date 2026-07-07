package com.rasp.commons;

/**
 * 攻击类型枚举
 * 
 * 定义了 RASP 检测的所有攻击类型，每个枚举值对应一类安全威胁。
 * 用于告警分类、策略匹配和统计聚合。
 */
public enum AttackType {
    
    /** SQL 注入攻击 - 通过构造恶意 SQL 语句篡改数据库查询逻辑 */
    SQL_INJECTION("SQL Injection", "sql"),
    
    /** 命令注入攻击 - 在应用层注入操作系统命令 */
    COMMAND_INJECTION("Command Injection", "cmd"),
    
    /** 反序列化攻击 - 通过恶意序列化数据执行任意代码 */
    DESERIALIZATION("Deserialization", "deser"),
    
    /** 文件操作攻击 - 路径遍历、任意文件读写 */
    FILE_OPERATION("File Operation", "file"),
    
    /** SSRF 攻击 - 服务端请求伪造，利用服务器发起内网请求 */
    SSRF("SSRF", "ssrf"),
    
    /** JNDI 注入攻击 - 通过 JNDI 查找加载远程恶意对象 */
    JNDI_INJECTION("JNDI Injection", "jndi"),
    
    /** 表达式注入 - SpEL/OGNL/MVEL 等表达式引擎注入 */
    EXPRESSION_INJECTION("Expression Injection", "expr"),
    
    /** XSS 跨站脚本攻击 */
    XSS("Cross-Site Scripting", "xss"),
    
    /** WebShell - 恶意脚本文件上传和访问 */
    WEBSHELL("WebShell", "webshell"),
    
    /** 内存马 - 无文件 Webshell，动态注册 Servlet/Filter */
    MEMORY_SHELL("Memory Shell", "memshell"),
    
    /** 其他/未知攻击类型 */
    UNKNOWN("Unknown", "unknown");

    private final String displayName;
    private final String shortCode;

    AttackType(String displayName, String shortCode) {
        this.displayName = displayName;
        this.shortCode = shortCode;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getShortCode() {
        return shortCode;
    }

    /**
     * 通过短码查找攻击类型
     */
    public static AttackType fromShortCode(String shortCode) {
        for (AttackType type : values()) {
            if (type.shortCode.equalsIgnoreCase(shortCode)) {
                return type;
            }
        }
        return UNKNOWN;
    }
}
