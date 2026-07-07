package com.rasp.agent;

import com.rasp.agent.bootstrap.AgentBootstrap;
import com.rasp.core.hook.HookPoint;
import com.rasp.core.hook.HookRegistry;
import com.rasp.hooks.RaspGuard;
import com.rasp.hooks.transformer.HookClassVisitor;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;
import java.util.List;

/**
 * RASP Premain Agent 入口
 * 
 * 通过 -javaagent:rasp-agent.jar 参数在 JVM 启动时加载。
 * premain 方法在 main 方法之前执行。
 * 
 * 启动参数（通过 -D 系统属性传递）：
 * -Drasp.config=/path/to/rasp.yml    配置文件路径
 * -Drasp.server=http://host:port    管理后台地址
 * -Drasp.app.name=my-app            应用名称
 * -Drasp.debug=true                 调试模式
 */
public class RaspPremain {

    /** Agent 版本号 */
    public static final String VERSION = "1.0.0-SNAPSHOT";

    /** Agent 启动时间戳 */
    private static volatile long startTimeMillis;

    /** Instrumentation 实例引用（全局） */
    private static volatile Instrumentation instrumentation;

    /**
     * JVM 启动时回调（premain 模式）
     * 
     * @param agentArgs -javaagent 传入的参数
     * @param inst      Instrumentation 实例
     */
    public static void premain(String agentArgs, Instrumentation inst) {
        startTimeMillis = System.currentTimeMillis();
        instrumentation = inst;
        System.out.println("[RASP Agent v" + VERSION + "] Starting premain mode...");

        try {
            // 1. 初始化引导器
            AgentBootstrap bootstrap = new AgentBootstrap(agentArgs, inst);
            bootstrap.init();

            // 2. 将 agent jar 添加到 BootstrapClassLoader 的搜索路径
            //    这样 Hook java.io.File 等 Bootstrap 加载的类时才能访问 agent 中的代码
            bootstrap.addToBootstrapClassLoader();

            // 3. 注册 ClassFileTransformer
            RaspClassFileTransformer transformer = new RaspClassFileTransformer();
            inst.addTransformer(transformer, true); // true = 支持 retransform

            // 4. 对已加载的类执行 retransform（如 java.io.FileInputStream 可能已加载）
            bootstrap.retransformLoadedClasses(inst, transformer);

            // 5. 开启全局 Hook 开关
            RaspGuard.setEnabled(true);
            HookRegistry.getInstance().setGlobalHookEnabled(true);

            // 6. 启动心跳线程（向管理后台上报状态）
            bootstrap.startHeartbeat();

            System.out.println("[RASP Agent v" + VERSION + "] Started successfully in "
                + (System.currentTimeMillis() - startTimeMillis) + "ms");

        } catch (Exception e) {
            // 启动失败不阻塞应用启动（优雅降级）
            System.err.println("[RASP Agent] Failed to start: " + e.getMessage());
            e.printStackTrace(System.err);
        }
    }

    /**
     * 核心 ClassFileTransformer
     * 
     * 对每个加载的类进行检查，对匹配 HookPoint 的类进行字节码增强。
     * 
     * 性能关键点：
     * - L1 过滤：className 不在 hookTargetClasses 中 → <100ns 返回 null
     * - L2 过滤：已处理的类签名缓存 → 避免重复 ASM 解析
     * - 异常隔离：单个类的 transform 失败不影响其他类
     */
    static class RaspClassFileTransformer implements ClassFileTransformer {

        private final HookRegistry registry = HookRegistry.getInstance();

        @Override
        public byte[] transform(ClassLoader loader, String className,
                Class<?> classBeingRedefined, ProtectionDomain protectionDomain,
                byte[] classfileBuffer) {

            // 跳过 RASP 自身的类
            if (className != null && className.startsWith("com/rasp/")) {
                return null;
            }

            // 跳过 JDK 内部类（除了需要 Hook 的）
            if (className != null && className.startsWith("java/lang/invoke/")) {
                return null;
            }

            // L1 快速过滤
            if (!registry.isHookTarget(className)) {
                return null;
            }

            List<HookPoint> hookPoints = registry.getHookPoints(className);
            if (hookPoints == null || hookPoints.isEmpty()) {
                return null;
            }

            // 全局开关未开启时，只记录不做修改
            if (!registry.isGlobalHookEnabled()) {
                return null;
            }

            try {
                ClassReader cr = new ClassReader(classfileBuffer);
                ClassWriter cw = new ClassWriter(cr,
                    ClassWriter.COMPUTE_MAXS | ClassWriter.COMPUTE_FRAMES);

                HookClassVisitor visitor = new HookClassVisitor(
                    org.objectweb.asm.Opcodes.ASM9, cw, className, hookPoints);
                cr.accept(visitor, ClassReader.EXPAND_FRAMES);

                return cw.toByteArray();

            } catch (Exception e) {
                // 异常隔离：单个 transform 失败不阻塞整个类加载
                System.err.println("[RASP Agent] Failed to transform class: "
                    + className + " - " + e.getMessage());
                return null;
            }
        }
    }

    public static long getStartTimeMillis() { return startTimeMillis; }
    public static String getVersion() { return VERSION; }
}
