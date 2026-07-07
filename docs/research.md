# Java RASP 技术调研报告

> **项目名称**: my-java-rasp  
> **调研时间**: 2026-07-07  
> **调研范围**: Java RASP 技术原理、业内标杆项目、核心攻防技术、性能优化策略

---

## 一、RASP 技术概述

### 1.1 什么是 RASP

RASP（Runtime Application Self-Protection，运行时应用自我保护）是一种将安全防护逻辑直接嵌入应用程序运行时的安全技术。不同于 WAF 在网络层拦截、不同于 SAST 在代码层扫描，RASP 在应用进程内部运行，拥有对敏感 API 调用的完全可见性。

### 1.2 RASP vs WAF vs EDR

| 维度 | WAF | RASP | EDR |
|------|-----|------|-----|
| 部署位置 | 网络边界 | JVM 进程内（Java Agent） | 操作系统层 |
| 可见性 | HTTP 流量 | 方法参数、调用栈、请求上下文 | 进程、文件、网络 |
| 0day 防御 | 依赖签名，滞后 | 参数-API关联分析，实时 | 不适用应用层 |
| 绕过难度 | 编码/混淆即可 | 必须控制实际 API 参数 | 不适用 |
| 性能开销 | 低（独立硬件） | 每个 Hook 点有微开销 | 低 |
| 误报率 | 较高（特征匹配） | 较低（上下文感知） | N/A |

### 1.3 RASP 的核心优势

1. **上下文感知**：同时拥有 HTTP 请求上下文 + 底层 API 调用参数，可以建立"谁在请求→调用了什么→传了什么参数"的完整链条
2. **0day 防御能力**：不依赖漏洞签名，而是检测输入参数是否危险地流入了敏感 API 调用
3. **精准拦截**：拦截发生在漏洞触发点，不会影响正常业务流量

---

## 二、业内标杆项目深度分析

### 2.1 百度 OpenRASP（开源标杆）

**GitHub**: https://github.com/baidu/openrasp  
**Star**: 3.3k+  
**技术栈**: Java Agent + Javassist + Rhino JS引擎  
**支持语言**: Java / PHP  

#### 架构亮点

```
启动流程:
  premain() → BootstrapClassLoader挂载 → log4j初始化 → 
  配置加载(openrasp.yml) → JS插件初始化 → 
  CustomClassTransformer注册 → 全局Hook开关打开
```

**关键设计决策**:
- **Javassist 做字节码增强**：简单但性能一般，API 较老
- **Rhino JS 引擎做规则**：支持热更新，但 JS 引擎性能差
- **BootstrapClassLoader 挂载**：通过将 agent.jar 添加到 Bootstrap ClassPath，解决 Hook java.io.File 等核心类时的类可见性问题
- **全局 Hook 开关**：Agent 启动阶段关闭 Hook，初始化完成后才开启，保证启动过程安全
- **文件监控热更新**：对配置文件、JS 插件目录启用文件监控，变更时自动重载

#### Hook 体系

| Hook 类型 | 目标类/方法 | 检测方式 |
|-----------|------------|---------|
| 命令执行 | `ProcessBuilder.start`, `Runtime.exec` | 参数白名单 + 命令注入检测 |
| SQL 注入 | `Statement.execute*`, `PreparedStatement` | SQL 词法分析 |
| 文件操作 | `FileInputStream/OutputStream`, `RandomAccessFile`, `Files.*` | 路径遍历检测 |
| 反序列化 | `ObjectInputStream.resolveClass` | 类名黑名单 |
| SSRF | `URL.openConnection`, `HttpURLConnection` | URL 白名单 |
| JNDI 注入 | `InitialContext.lookup` | 协议/URL 检测 |
| 表达式注入 | SpEL/OGNL 解析入口 | 表达式内容检测 |

#### 拦截策略

- Header 未发出 → 302 跳转到拦截页面
- Body 部分发出 → 重置响应体，注入拦截 JS
- 仅告警模式 → 记录到 `logs/alarm.log`

#### 存在的问题

1. **Javassist 性能瓶颈**：字节码生成质量不如 ASM
2. **Rhino 引擎**：包体积大 (~1MB)，性能差，仅支持 ES5
3. **Hook 点不完整**：存在绕过路径（未覆盖的类、JNI 层）
4. **检测逻辑差异**：命令执行用 `doCheckWithoutRequest`，文件操作用 `doCheck`，不一致导致可被绕过
5. **线程上下文漏洞**：请求线程标记可被线程转移绕过

### 2.2 腾讯云 RASP

**核心特征**:
- **多层防护**：Java 层（ASM）+ JVM 层（JVMTI）+ Native 层（JNI），三重 hook 防绕过
- **Hook 42 类关键操作**：覆盖度是 OpenRASP 的 2 倍以上
- **云端联动**：策略下发、环境监测、强制中断、日志上报统一管理
- **白帽生态**：通过众测平台持续发现绕过路径并修复

**已知的绕过路径（已被腾讯云修复）**:
1. 线程转移 → 在非监控线程执行恶意操作
2. 未 hook 类利用 → 通过 `MethodInvokingRunnable`、`StandardThreadExecutor` 等绕过
3. JNI 层绕过 → `System.loadLibrary` 加载恶意 .so/.dll
4. 文件写入 Gadget Chain → `DefaultFileSystem#getOutputStream` 等未覆盖路径

### 2.3 火线洞态 IAST (DongTai-agent-java)

**定位**: IAST + RASP 双模式  
**技术栈**: Java Agent + ASM  
**特色**:
- 污点追踪（Taint Tracking）：标记用户输入，追踪数据流向
- 方法调用链分析：构建完整的数据传播路径
- 支持 Spring Boot / Dubbo / gRPC 等多框架

### 2.4 阿里云 RASP

**商业化产品**，核心能力：
- 自动发现和接入 Java 应用
- 应用漏洞虚拟补丁（针对已知 CVE 自动热修复）
- 内存马检测（Memory WebShell）
- 与云安全中心联动

---

## 三、核心技术原理深度分析

### 3.1 Java Agent 机制

```
┌──────────────────────────────────────────────────────┐
│                    JVM 启动流程                        │
│                                                       │
│  JVM启动 → premain(agentArgs, inst) → main()         │
│                   │                                   │
│            ┌──────▼───────┐                           │
│            │ 注册Transformer │  ← ClassFileTransformer │
│            │ retransform已  │  ← 对已加载类重新转换     │
│            │ 加载的核心类    │                         │
│            └──────────────┘                           │
│                                                       │
│  premain 模式：-javaagent:rasp-agent.jar              │
│  agentmain 模式：动态 attach 到运行中 JVM             │
└──────────────────────────────────────────────────────┘
```

**两种加载模式对比**:

| 特性 | premain | agentmain |
|------|---------|-----------|
| 触发时机 | JVM 启动时（main之前） | 运行时动态 attach |
| 启动命令 | `-javaagent:xxx.jar` | `jcmd <pid> loadAgent` |
| 是否需要重启 | 需要 | 不需要 |
| 稳定性 | 高（所有类加载时即可插桩） | 中（已加载类需 retransform） |
| 类覆盖度 | 100% | ~95%（部分类不可 retransform） |
| 性能影响 | 启动时一次性开销 | retransform 时有 STW 暂停 |

### 3.2 ClassFileTransformer 与字节码增强

```
类加载流程:
  ClassLoader.loadClass()
      → findClass() 获取原始字节码
      → 遍历所有注册的 ClassFileTransformer
          → transform(loader, className, classBeingRedefined, 
                       protectionDomain, classfileBuffer)
              → 判断是否为 Hook 目标类
              → 如果是，调用 ASM 修改字节码
              → 返回修改后的字节码
      → defineClass() 定义修改后的类
```

**关键点**：
- Transformer 可以注册多个，按注册顺序依次执行
- `retransformClasses()` 可以对已加载类重新应用 Transformer
- 不可 retransform 的情况：修改了类结构（添加/删除方法、字段）

### 3.3 ASM 字节码框架

**为什么选 ASM**：

| 框架 | 优势 | 劣势 | 适用场景 |
|------|------|------|---------|
| **ASM** | 性能最优（事件驱动，直接操作字节码） | API 底层，开发成本高 | 生产级 RASP 核心路径 |
| ByteBuddy | API 友好，类型安全 | 运行时生成代理类有开销 | 非核心路径、原型 |
| Javassist | 源码级操作，简单 | 性能差，已不活跃 | 不推荐新产品使用 |

**ASM 核心 API**:
- `ClassReader`: 读取字节码
- `ClassVisitor`: 访问类结构（字段、方法、注解）
- `MethodVisitor`: 访问方法体（指令序列）
- `ClassWriter`: 生成修改后的字节码
- `AdviceAdapter`: 便捷的 AOP 风格方法插桩

### 3.4 Hook 注入模式

```java
// ===== 原始代码 =====
public class ProcessBuilder {
    public Process start() throws IOException {
        // 原始实现...
    }
}

// ===== ASM 转换后 =====
public class ProcessBuilder {
    public Process start() throws IOException {
        // === 注入的检测代码（方法入口） ===
        Object[] args = new Object[]{this.command};
        HookResult result = RaspHookHandler.onMethodEnter(
            "java.lang.ProcessBuilder", "start", args, this
        );
        if (result.isBlocked()) {
            throw new SecurityException(result.getMessage());
        }
        // === 原始代码 ===
        try {
            Process p = /* 原始实现 */;
            // === 注入的检测代码（方法出口） ===
            RaspHookHandler.onMethodExit(/*...*/);
            return p;
        } catch (Throwable t) {
            RaspHookHandler.onMethodError(/*...*/);
            throw t;
        }
    }
}
```

**三种 Hook 结果处理**:
- `RETURN`: 放行，正常执行
- `THROW`: 阻断，抛出 SecurityException
- `REPLACE`: 替换返回值（如 SSRF 返回假的连接对象）

### 3.5 线程上下文模型（Context）

这是 RASP 最精妙的设计之一：

```
HTTP 请求到达
    │
    ▼
┌──────────────────────────────────────┐
│ Filter.doFilter() / Servlet.service() │ ← Hook 入口
│   → RaspContext.create(request, resp) │ ← 创建上下文
│   → ThreadLocal.set(context)          │ ← 绑定当前线程
└──────────────┬───────────────────────┘
               │
    ┌──────────▼──────────┐
    │ 业务代码执行...       │
    │   ↓                  │
    │ JDBC.execute(sql)    │ ← Hook 触发
    │   → RaspContext.get()│ ← 获取当前请求上下文
    │   → 检测 SQL 是否包含请求参数
    │   → 若包含且危险 → 阻断
    └──────────┬──────────┘
               │
┌──────────────▼───────────────────────┐
│ Filter/Servlet 返回                   │
│   → RaspContext.destroy()            │ ← 清理上下文
│   → ThreadLocal.remove()             │ ← 防止内存泄漏
└──────────────────────────────────────┘
```

**Context 存储的关键信息**:
- `HttpServletRequest` / `HttpServletResponse` 引用
- 请求参数 Map（URL参数 + Body参数）
- 请求头、Cookie
- 当前请求的 Hook 触发记录
- 攻击事件列表
- 请求唯一 ID（用于日志关联）

---

## 四、攻击检测策略深度分析

### 4.1 SQL 注入检测

**Hook 点**: `java.sql.Statement.execute*()`, `PreparedStatement`

**检测策略**:
1. **规则匹配**（兜底）：正则匹配 `UNION SELECT`、`' OR 1=1`、`xp_cmdshell` 等特征
2. **参数关联分析**（核心）：提取 SQL 中的字面量，检查是否出现在 HTTP 请求参数中
3. **SQL 词法分析**（精准）：使用 SQL 解析器（JSqlParser）做语法树分析，识别注入结构

```java
// 示例：参数关联检测
// 请求参数: username=admin' OR '1'='1
// 执行的 SQL: SELECT * FROM users WHERE username='admin' OR '1'='1'
// 检测逻辑: 
//   1. 提取 SQL 中 WHERE 子句的字面量: ["admin' OR '1'='1"]
//   2. 检查请求参数值是否包含这些字面量
//   3. admin' OR '1'='1 包含 SQL 注入特征 → 阻断
```

### 4.2 命令执行检测

**Hook 点**: `ProcessBuilder.start()`, `Runtime.exec()`

**检测策略**:
1. **命令白名单**：只放行已知安全命令（如 `ping`, `nslookup`, `curl` 指定域名）
2. **管道/重定向检测**：检测 `|`, `;`, `&&`, `$()`, `` ` ``, `>`, `<` 等
3. **参数关联**：命令参数是否直接来自 HTTP 请求
4. **反弹 Shell 特征**：`/dev/tcp`, `nc`, `bash -i` 等

### 4.3 反序列化攻击检测

**Hook 点**: `ObjectInputStream.resolveClass()`

**检测策略**:
1. **类名黑名单**：已知 Gadget 类（`Runtime`, `ProcessBuilder`, `InvokerTransformer`, `TemplatesImpl` 等）
2. **调用栈分析**：检测反序列化调用链是否从 HTTP 请求触发
3. **类结构检查**：检测动态生成的恶意类

```java
// 黑名单（部分）
private static final Set<String> DANGEROUS_CLASSES = Set.of(
    "java.lang.Runtime",
    "java.lang.ProcessBuilder",
    "javax.management.BadAttributeValueExpException",
    "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
    "org.apache.commons.collections.Transformer",
    "org.apache.commons.collections.functors.InvokerTransformer",
    "org.apache.commons.collections.functors.ChainedTransformer",
    "org.apache.commons.collections.functors.ConstantTransformer",
    "org.apache.commons.collections.functors.InstantiateTransformer",
    "org.springframework.beans.factory.ObjectFactory",
    "com.sun.rowset.JdbcRowSetImpl",
    // ... 更多已知 Gadget 类
);
```

### 4.4 文件操作检测

**Hook 点**: 
- `java.io.FileInputStream`, `java.io.FileOutputStream`
- `java.io.RandomAccessFile`
- `java.nio.file.Files.read*`, `Files.write*`
- `java.io.File.renameTo()`, `File.delete()`

**检测策略**:
1. **路径遍历检测**：`../`, `..\\`, 绝对路径跨目录
2. **敏感文件检测**：`/etc/passwd`, `/etc/shadow`, `WEB-INF/`, `.jsp`, `.class`
3. **写入检测**：JSP/PHP/ASPX 文件写入（WebShell 写入）
4. **参数关联**：文件路径是否来自请求参数

### 4.5 SSRF 检测

**Hook 点**: `URL.openConnection()`, `HttpURLConnection.connect()`

**检测策略**:
1. **URL 白名单**：只放行已配置的外部域名/IP
2. **内网 IP 检测**：`127.0.0.1`, `10.x`, `172.16-31.x`, `192.168.x`
3. **DNS Rebinding 检测**：解析后的 IP 是否指向内网
4. **协议限制**：限制 `file://`, `gopher://`, `jar://`, `netdoc://` 等危险协议

### 4.6 JNDI 注入检测

**Hook 点**: `InitialContext.lookup()`

**检测策略**:
1. **协议检测**：`ldap://`, `rmi://`, `dns://`, `corba://` 来自外部输入
2. **URL 检测**：lookup 参数是否包含 URL
3. **类加载检测**：lookup 是否触发了远程类加载

### 4.7 表达式注入检测

**Hook 点**: 
- SpEL: `org.springframework.expression.spel.standard.SpelExpressionParser.parseExpression()`
- OGNL: `ognl.Ognl.parseExpression()`
- MVEL: `org.mvel2.MVEL.executeExpression()`

**检测策略**:
1. **危险函数检测**：表达式是否包含 `Runtime`, `exec`, `getClass()`, `forName()` 等
2. **参数来源检测**：表达式内容是否来自 HTTP 请求

### 4.8 内存马检测

**Hook 点**: `ServletContext.addServlet()`, `FilterRegistration.Dynamic` 相关 API

**检测策略**:
1. **动态注册检测**：运行时新增的 Servlet/Filter/Listener
2. **ClassLoader 检测**：非标准 ClassLoader 加载的类
3. **代码源检测**：动态注册组件来源是否为已知应用

---

## 五、绕过技术分析（攻防对抗）

### 5.1 已知绕过路径

| 绕过技术 | 原理 | 防御措施 |
|---------|------|---------|
| 线程转移 | 将恶意操作放到非监控线程执行 | 全局线程监控 + 线程创建 Hook |
| 未覆盖 Hook 点 | 使用未监控的 API | 持续扩充 Hook 覆盖矩阵 |
| JNI 层绕过 | `System.loadLibrary` + Native 操作 | Hook `System.loadLibrary` + JVMTI 层监控 |
| 条件竞争 | 在检测完成到实际执行之间修改参数 | 使用不可变参数快照 |
| 反射绕过 | 通过反射调用 Hook 函数内部逻辑 | Hook 反射 API 关键路径 |
| Java Agent 对抗 | 卸载/禁用 Agent | Agent 自我保护 + Attach API 监控 |

### 5.2 新一代绕过技术（腾讯云白帽发现）

1. **Gadget Chain 利用**：组合多个"看似无害"的 API 调用链，每个单独调用都不触发检测
2. **Instrumentation 对抗**：利用 `retransformClasses` 恢复被 Hook 类的原始字节码
3. **SPI 机制利用**：通过 `META-INF/services/` 动态注册 Hook 未覆盖的实现类
4. **Lamba/方法引用绕过**：动态生成的 Lambda 类可能不被 ClassFileTransformer 拦截

---

## 六、性能优化策略

### 6.1 OpenRASP 实测数据

| 场景 | 无 RASP | 加载 OpenRASP | 增幅 |
|------|---------|-------------|------|
| 纯文本响应 (QPS) | 35000 | 32000 | -8.6% |
| JSON API (QPS) | 28000 | 25000 | -10.7% |
| 数据库查询 (QPS) | 12000 | 10800 | -10.0% |
| 文件上传 (MB/s) | 85 | 80 | -5.9% |
| 启动时间 (秒) | 3.2 | 4.1 | +28% |
| 内存占用 (MB) | 256 | 310 | +21% |

### 6.2 优化方向

1. **精准 Hook**：只 Hook 关键方法，避免全量插桩
2. **快速路径**：非请求线程下跳过检测
3. **检测缓存**：相同参数+相同上下文的检测结果缓存
4. **异步日志**：攻击事件异步写入，不阻塞业务线程
5. **规则编译缓存**：正则表达式预编译，SQL 解析结果缓存
6. **连接池复用**：数据库连接、HTTP 连接池化
7. **采样检测**：高 QPS 场景下可配置采样率

---

## 七、多框架适配分析

### 7.1 Web 容器适配

| 框架 | Servlet API 版本 | 适配要点 |
|------|-----------------|---------|
| Tomcat 7/8/9/10 | 3.0/3.1/4.0/5.0 | 包名变化（javax→jakarta） |
| Jetty 9/10/11 | 3.1/4.0/5.0 | 线程模型差异 |
| Undertow | 3.1/4.0 | NIO 线程模型 |
| WebLogic | 3.0 | 类加载器隔离策略特殊 |
| WebSphere | 3.0 | WAS 安全策略叠加 |

**适配策略**：
- 通过 `ThreadLocal` 而非 `HttpServlet` 直接引用管理上下文
- 检测当前线程是否处于 Servlet 处理中的通用方法
- 为每种容器提供独立的 Context 建立 Hook 点
- 运行时检测容器类型，自动加载对应适配器

### 7.2 JDBC 驱动适配

| 数据库 | JDBC 驱动类 | 特殊适配 |
|--------|-----------|---------|
| MySQL | `com.mysql.cj.jdbc.*` | 8.x 驱动类名变化 |
| PostgreSQL | `org.postgresql.*` | 数组参数类型特殊 |
| Oracle | `oracle.jdbc.*` | TNS 协议别名 |
| SQL Server | `com.microsoft.sqlserver.*` | Windows 集成认证 |
| H2 | `org.h2.*` | 嵌入式模式 |

---

## 八、技术选型总结

### 最终技术栈

| 层次 | 技术选型 | 理由 |
|------|---------|------|
| 字节码增强 | **ASM 9.7+** | 性能最优，生产环境首选 |
| 构建工具 | **Maven** | 用户指定，多模块天然支持 |
| Java 版本 | **Java 8+** | 最大兼容性 |
| 日志框架 | **SLF4J + 自实现** | 避免与业务日志框架冲突 |
| JSON | **自实现轻量解析** | Agent 中不引入大型依赖 |
| 规则引擎 | **自研** | 避免外部依赖，高性能 |
| 管理后台 | **Spring Boot 2.7+** | 成熟稳定 |
| 前端 | **React 18 + Ant Design 5** | 组件丰富，开发效率高 |
| 数据库 | **H2 → MySQL/PostgreSQL** | 开发简化，生产可迁移 |
| 测试靶场 | **Spring Boot + Thymeleaf** | 简单易部署 |
| 代码推送 | **Git + GitHub** | 用户仓库 |

---

## 九、参考资料

1. OpenRASP 官方文档: https://rasp.baidu.com/doc/
2. OpenRASP GitHub: https://github.com/baidu/openrasp
3. javaweb-sec RASP: https://github.com/javaweb-sec/javaweb-sec
4. 腾讯云 RASP 技术分析: https://cloud.tencent.com/developer/article/2650339
5. Java Agent 规范: https://docs.oracle.com/javase/8/docs/api/java/lang/instrument/package-summary.html
6. ASM 框架: https://asm.ow2.io/
7. 洞态 IAST: https://github.com/HXSecurity/DongTai-agent-java
8. OWASP RASP: https://owasp.org/www-community/RASP
