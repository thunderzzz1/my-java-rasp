package com.rasp.agent.bootstrap;

import com.rasp.core.hook.HookPoint;
import com.rasp.core.hook.HookRegistry;
import com.rasp.detector.command.CommandDetector;
import com.rasp.detector.deserialization.DeserializationDetector;
import com.rasp.detector.sql.SqlDetector;

import java.io.File;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.util.jar.JarFile;

/**
 * Agent 引导器
 * 
 * 负责 Agent 的初始化流程：
 * 1. 解析配置参数
 * 2. Bootstrap ClassLoader 挂载
 * 3. 注册默认 Hook 点
 * 4. 初始化检测器
 * 5. Retransform 已加载的核心类
 * 6. 启动心跳
 */
public class AgentBootstrap {

    private final String agentArgs;
    private final Instrumentation instrumentation;

    private String configPath;
    private String serverUrl;
    private String appName;
    private boolean debugMode;

    public AgentBootstrap(String agentArgs, Instrumentation instrumentation) {
        this.agentArgs = agentArgs;
        this.instrumentation = instrumentation;
    }

    /**
     * 完整初始化流程
     */
    public void init() {
        // 1. 解析配置
        parseConfig();

        // 2. 注册所有默认 Hook 点和检测器
        registerDefaultHooks();
    }

    /**
     * 解析启动参数和系统属性
     */
    private void parseConfig() {
        this.configPath = System.getProperty("rasp.config", "rasp.yml");
        this.serverUrl = System.getProperty("rasp.server", "http://localhost:8080");
        this.appName = System.getProperty("rasp.app.name", "unknown");
        this.debugMode = Boolean.parseBoolean(System.getProperty("rasp.debug", "false"));

        if (debugMode) {
            System.out.println("[RASP Agent] Configuration:");
            System.out.println("  config: " + configPath);
            System.out.println("  server: " + serverUrl);
            System.out.println("  app: " + appName);
        }
    }

    /**
     * 将 agent jar 添加到 BootstrapClassLoader 的 ClassPath
     * 
     * 这是 RASP 最重要的初始化步骤之一。
     * 没有这个操作，Hook java.io.File、java.lang.Runtime 等
     * 由 BootstrapClassLoader 加载的类时会抛出 ClassNotFoundException。
     */
    public void addToBootstrapClassLoader() {
        try {
            // 获取 agent jar 的路径
            String agentJarPath = getAgentJarPath();
            if (agentJarPath != null) {
                JarFile jarFile = new JarFile(new File(agentJarPath));
                instrumentation.appendToBootstrapClassLoaderSearch(jarFile);
                if (debugMode) {
                    System.out.println("[RASP Agent] Added to BootstrapClassLoader: " + agentJarPath);
                }
            }
        } catch (Exception e) {
            System.err.println("[RASP Agent] Failed to add to BootstrapClassLoader: " + e.getMessage());
        }
    }

    /**
     * 获取当前 agent jar 的路径
     */
    private String getAgentJarPath() {
        try {
            // 从系统属性中获取（-javaagent 传递时会设置）
            String path = System.getProperty("sun.java.command");
            // 回退：从 classpath 中推断
            if (path == null) {
                path = AgentBootstrap.class.getProtectionDomain()
                    .getCodeSource().getLocation().getPath();
            }
            return path;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 注册所有默认的 Hook 点和检测器
     */
    private void registerDefaultHooks() {
        HookRegistry registry = HookRegistry.getInstance();

        // ===== P0: SQL 注入 =====
        registry.register(HookPoint.builder()
            .className("java.sql.Statement")
            .methodName("executeQuery")
            .handler(event -> new SqlDetector().detect(event, com.rasp.core.context.RaspContext.get()))
            .build());
        registry.register(HookPoint.builder()
            .className("java.sql.Statement")
            .methodName("executeUpdate")
            .handler(event -> new SqlDetector().detect(event, com.rasp.core.context.RaspContext.get()))
            .build());
        registry.register(HookPoint.builder()
            .className("java.sql.Statement")
            .methodName("execute")
            .handler(event -> new SqlDetector().detect(event, com.rasp.core.context.RaspContext.get()))
            .build());

        // ===== P0: 命令执行 =====
        registry.register(HookPoint.builder()
            .className("java.lang.ProcessBuilder")
            .methodName("start")
            .handler(event -> new CommandDetector().detect(event, com.rasp.core.context.RaspContext.get()))
            .build());
        registry.register(HookPoint.builder()
            .className("java.lang.Runtime")
            .methodName("exec")
            .handler(event -> new CommandDetector().detect(event, com.rasp.core.context.RaspContext.get()))
            .build());

        // ===== P0: 反序列化 =====
        registry.register(HookPoint.builder()
            .className("java.io.ObjectInputStream")
            .methodName("resolveClass")
            .handler(event -> new DeserializationDetector().detect(event, com.rasp.core.context.RaspContext.get()))
            .build());

        if (debugMode) {
            System.out.println("[RASP Agent] Registered " + registry.getHookCount() + " hook points");
        }
    }

    /**
     * 对已加载的类执行 retransform
     * 
     * JVM 启动时会预加载很多核心类（如 java.io.FileInputStream），
     * 这些类的加载发生在我们注册 Transformer 之后但在 premain 完成之前。
     * 需要手动触发 retransform 来对这些类应用 Hook。
     */
    public void retransformLoadedClasses(Instrumentation inst, ClassFileTransformer transformer) {
        try {
            Class<?>[] loadedClasses = inst.getAllLoadedClasses();
            java.util.List<Class<?>> toRetransform = new java.util.ArrayList<>();

            HookRegistry registry = HookRegistry.getInstance();
            for (Class<?> clazz : loadedClasses) {
                String internalName = clazz.getName().replace('.', '/');
                if (registry.isHookTarget(internalName)) {
                    toRetransform.add(clazz);
                }
            }

            if (!toRetransform.isEmpty() && inst.isRetransformClassesSupported()) {
                inst.retransformClasses(toRetransform.toArray(new Class<?>[0]));
                if (debugMode) {
                    System.out.println("[RASP Agent] Retransformed " + toRetransform.size() + " loaded classes");
                }
            }
        } catch (Exception e) {
            System.err.println("[RASP Agent] Retransform failed (non-fatal): " + e.getMessage());
        }
    }

    /**
     * 启动心跳线程
     * 
     * 定期向 rasp-server 上报 Agent 状态信息。
     */
    public void startHeartbeat() {
        Thread heartbeatThread = new Thread(() -> {
            while (true) {
                try {
                    Thread.sleep(30000); // 30 秒间隔
                    // TODO: 实现 HTTP 心跳上报
                    if (debugMode) {
                        System.out.println("[RASP Agent] Heartbeat: "
                            + HookRegistry.getInstance().getHookCount() + " hooks active");
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }, "rasp-heartbeat");
        heartbeatThread.setDaemon(true);
        heartbeatThread.start();
    }
}
