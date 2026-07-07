package com.rasp.detector.jndi;

import com.rasp.commons.AttackType;
import com.rasp.commons.Severity;
import com.rasp.core.context.HookEvent;
import com.rasp.core.context.RaspContext;
import com.rasp.core.detector.DetectResult;
import com.rasp.detector.AbstractDetector;

import java.util.*;

/**
 * JNDI 注入检测器
 * 
 * 检测通过 JNDI lookup 加载远程恶意对象的攻击。
 * 这是 Log4Shell (CVE-2021-44228) 等漏洞的核心利用途径。
 * 
 * 全局检测：JNDI 注入可能在非请求线程触发（如日志处理线程）。
 */
public class JndiDetector extends AbstractDetector {

    /** JNDI 支持的远程协议 */
    private static final Set<String> REMOTE_PROTOCOLS = new HashSet<>(Arrays.asList(
        "ldap", "ldaps", "rmi", "dns", "corba", "iiop", "nis"
    ));

    /** 绝对安全的 JNDI 前缀（白名单） */
    private static final Set<String> SAFE_PREFIXES = new HashSet<>(Arrays.asList(
        "java:", "java:comp/", "java:global/"
    ));

    public JndiDetector() {
        super(AttackType.JNDI_INJECTION, "jndi-detector");
    }

    @Override
    protected boolean isGlobalDetect() {
        return true; // JNDI 注入可能在任何线程中触发
    }

    @Override
    protected DetectResult doDetect(HookEvent event, RaspContext context) {
        Object arg = event.getArgument(0);
        if (!(arg instanceof String)) {
            return DetectResult.PASS;
        }

        String name = (String) arg;
        if (name == null || name.isEmpty()) {
            return DetectResult.PASS;
        }

        String lower = name.toLowerCase().trim();

        // 1. 白名单快速放行
        for (String safe : SAFE_PREFIXES) {
            if (lower.startsWith(safe)) {
                return DetectResult.PASS;
            }
        }

        // 2. 检测远程协议
        for (String protocol : REMOTE_PROTOCOLS) {
            if (lower.startsWith(protocol + "://") || lower.startsWith(protocol + ":/")) {
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("jndi_name", name);
                evidence.put("protocol", protocol);
                return DetectResult.block(AttackType.JNDI_INJECTION, Severity.HIGH,
                    "JNDI remote object loading detected: " + truncate(name), evidence);
            }
        }

        // 3. 检测 URL 特征（包含 :// 的任意协议）
        if (lower.contains("://") && !lower.startsWith("java:")) {
            return DetectResult.block(AttackType.JNDI_INJECTION, Severity.HIGH,
                "JNDI lookup with URL scheme: " + truncate(name),
                Collections.singletonMap("jndi_name", name));
        }

        // 4. 参数关联
        if (context != null && context.isParamTainted(name)) {
            return DetectResult.block(AttackType.JNDI_INJECTION, Severity.HIGH,
                "JNDI lookup with user-controlled input: " + truncate(name),
                Collections.singletonMap("jndi_name", name));
        }

        return DetectResult.PASS;
    }

    private String truncate(String s) {
        return s.length() > 100 ? s.substring(0, 100) + "..." : s;
    }
}
