package com.rasp.detector.sql;

import com.rasp.commons.AttackType;
import com.rasp.commons.Severity;
import com.rasp.core.context.HookEvent;
import com.rasp.core.context.RaspContext;
import com.rasp.core.detector.DetectResult;
import com.rasp.detector.AbstractDetector;

import java.util.*;
import java.util.regex.Pattern;

/**
 * SQL 注入检测器
 * 
 * 三级检测策略：
 * L1: 正则特征匹配（快速过滤，拦截明显攻击）
 * L2: 参数关联分析（核心能力，检测用户输入是否带入了 SQL）
 * L3: SQL 语法分析（精准检测，但开销较大，按需启用）
 */
public class SqlDetector extends AbstractDetector {

    // ===== L1: 预编译 SQL 注入特征正则 =====
    private static final Pattern[] INJECTION_PATTERNS = {
        // UNION SELECT 联合查询注入
        Pattern.compile("(?i)\\bUNION\\s+(ALL\\s+)?SELECT\\b"),
        // OR 恒等式
        Pattern.compile("(?i)\\bOR\\b\\s+['\"]?\\d+['\"]?\\s*=\\s*['\"]?\\d+['\"]?"),
        // 注释截断（-- 后跟空格和任意字符）
        Pattern.compile("--\\s+\\S"),
        Pattern.compile("/\\*!.+\\*/"),
        // DROP/TRUNCATE
        Pattern.compile("(?i)\\bDROP\\s+(TABLE|DATABASE)\\b"),
        Pattern.compile("(?i)\\bTRUNCATE\\s+TABLE\\b"),
        // 存储过程调用
        Pattern.compile("(?i)\\bEXEC\\s*\\(?\\s*(sp_|xp_)"),
        // 数据库信息探测
        Pattern.compile("(?i)\\bINFORMATION_SCHEMA\\b"),
        // 堆叠查询
        Pattern.compile(";\\s*(SELECT|INSERT|UPDATE|DELETE|DROP)\\b", Pattern.CASE_INSENSITIVE),
        // 时间盲注
        Pattern.compile("(?i)\\bSLEEP\\s*\\(\\s*\\d+\\s*\\)"),
        Pattern.compile("(?i)\\bBENCHMARK\\s*\\(\\s*\\d+\\s*,"),
        // 报错注入函数
        Pattern.compile("(?i)\\b(EXTRACTVALUE|UPDATEXML)\\s*\\("),
        // 写文件/读文件
        Pattern.compile("(?i)\\bINTO\\s+(OUT|DUMP)FILE\\b"),
        Pattern.compile("(?i)\\bLOAD_FILE\\s*\\("),
    };

    // ===== L2: SQL 字符串字面量提取 =====
    private static final Pattern STRING_LITERAL = Pattern.compile("'([^']*?)'");

    // SQL 注入关键字黑名单（用于增强检测）
    private static final Set<String> SQL_KEYWORDS = new HashSet<>(Arrays.asList(
        "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "UNION",
        "CREATE", "ALTER", "TRUNCATE", "EXEC", "EXECUTE",
        "DECLARE", "WAITFOR", "SLEEP", "BENCHMARK"
    ));

    public SqlDetector() {
        super(AttackType.SQL_INJECTION, "sql-detector");
    }

    @Override
    protected DetectResult doDetect(HookEvent event, RaspContext context) {
        // 从 Hook 事件中提取 SQL 语句
        Object sqlObj = event.getArgument(0);
        if (!(sqlObj instanceof String)) {
            return DetectResult.PASS;
        }
        String sql = (String) sqlObj;
        if (sql.length() < 6) {
            return DetectResult.PASS;
        }

        // === L1: 正则特征快速匹配 ===
        for (Pattern pattern : INJECTION_PATTERNS) {
            if (pattern.matcher(sql).find()) {
                return block(Severity.HIGH,
                    "SQL Injection detected: pattern matched - " + pattern.pattern());
            }
        }

        // === L2: 参数关联分析（核心） ===
        if (context != null) {
            DetectResult result = checkParamTaint(sql, context);
            if (result != null) {
                return result;
            }
        }

        return DetectResult.PASS;
    }

    /**
     * 参数关联检测：
     * 提取 SQL 中的字符串字面量，检查是否直接来自 HTTP 请求参数
     */
    private DetectResult checkParamTaint(String sql, RaspContext context) {
        Map<String, String[]> params = context.getParameters();
        if (params == null || params.isEmpty()) {
            return null;
        }

        // 检查请求参数值是否原样出现在 SQL 中
        for (Map.Entry<String, String[]> entry : params.entrySet()) {
            for (String value : entry.getValue()) {
                if (value == null || value.length() < 2) {
                    continue;
                }
                // 只检查足够长的值（>2字符），避免误报
                if (value.length() > 2 && sql.contains(value)) {
                    // 还要确认这个值看起来像 SQL 注入 payload
                    if (isSuspiciousValue(value)) {
                        Map<String, Object> evidence = new LinkedHashMap<>();
                        evidence.put("sql", truncate(sql, 500));
                        evidence.put("param_name", entry.getKey());
                        evidence.put("param_value", truncate(value, 200));
                        evidence.put("detection_method", "param_taint");

                        return DetectResult.block(AttackType.SQL_INJECTION, Severity.HIGH,
                            "SQL Injection: request parameter '" + entry.getKey()
                                + "' value found in SQL statement",
                            evidence);
                    }
                }
            }
        }

        return null;
    }

    /**
     * 检查参数值是否包含 SQL 注入特征
     */
    private boolean isSuspiciousValue(String value) {
        String upper = value.toUpperCase();
        for (String keyword : SQL_KEYWORDS) {
            if (upper.contains(keyword)) {
                return true;
            }
        }
        // 检查单引号、分号等 SQL 特殊字符
        if (value.contains("'") || value.contains("\"") || value.contains(";") || value.contains("--")) {
            return true;
        }
        return false;
    }

    private String truncate(String s, int maxLen) {
        if (s == null) return null;
        return s.length() > maxLen ? s.substring(0, maxLen) + "...[truncated]" : s;
    }
}
