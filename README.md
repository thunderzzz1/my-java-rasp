# My-Java-RASP

> 生产级 Java 运行时应用自我保护系统 (Runtime Application Self-Protection)

## 概述

My-Java-RASP 是一个基于 Java Agent + ASM 字节码增强技术的运行时安全防护系统。通过注入到 JVM 中的探针，实时检测和阻断 SQL 注入、命令执行、反序列化等 10+ 类 Web 攻击。

## 架构

```
rasp-agent (Java Agent)
├── rasp-core      (核心引擎: Context/Hook/Config)
├── rasp-detector  (检测引擎: SQL/CMD/Deser/File/SSRF/JNDI/Expr)
├── rasp-hooks     (ASM Hook: 类转换器/方法插桩)
├── rasp-commons   (公共类型/告警事件)
├── rasp-server    (管理后台: Spring Boot)
├── rasp-web       (前端: React + Ant Design)
└── rasp-test-target (测试靶场)
```

## 快速开始

### 构建

```bash
# 编译全部模块
mvn clean package -DskipTests

# 仅构建 Agent（其他模块可选）
cd rasp-agent && mvn clean package -DskipTests
```

### 部署

```bash
# Premain 模式（推荐）
java -javaagent:rasp-agent/target/rasp-agent-1.0.0-SNAPSHOT.jar \
     -Drasp.server=http://rasp-server:8080 \
     -Drasp.app.name=my-app \
     -jar your-app.jar

# Agentmain 模式（动态注入，无需重启）
jcmd <PID> loadAgent rasp-agent/target/rasp-agent-1.0.0-SNAPSHOT.jar
```

## 支持的攻击检测

| 攻击类型 | Hook 目标 | 优先级 | 状态 |
|---------|-----------|--------|------|
| SQL 注入 | `Statement.execute*`, `PreparedStatement` | P0 | ✅ |
| 命令执行 | `ProcessBuilder.start`, `Runtime.exec` | P0 | ✅ |
| 反序列化 | `ObjectInputStream.resolveClass` | P0 | ✅ |
| 文件操作 | `FileInputStream`, `FileOutputStream`, `Files.*` | P0 | 🚧 |
| SSRF | `URL.openConnection`, `HttpURLConnection` | P1 | 🚧 |
| JNDI 注入 | `InitialContext.lookup` | P0 | 🚧 |
| 表达式注入 | SpEL/OGNL 解析入口 | P1 | 🚧 |
| XSS | `HttpServletResponse.getWriter` | P1 | 🚧 |
| WebShell | `Servlet.service` | P1 | 🚧 |
| 内存马 | `ServletContext.addServlet` | P2 | 🚧 |

## 技术栈

- **字节码**: ASM 9.7
- **构建**: Maven (Java 8+)
- **管理后台**: Spring Boot 2.7 + React 18 + Ant Design 5
- **数据库**: H2 (开发) / MySQL / PostgreSQL (生产)

## 文档

- [调研报告](docs/research.md)
- [技术设计文档](docs/design.md)

## License

MIT
