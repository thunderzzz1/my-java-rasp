package com.rasp.hooks;

import com.rasp.commons.AlarmEvent;
import com.rasp.commons.AttackType;
import com.rasp.commons.Severity;
import com.rasp.core.context.HookEvent;
import com.rasp.core.context.RaspContext;
import com.rasp.core.detector.DetectResult;
import com.rasp.core.hook.HookPoint;
import com.rasp.core.hook.HookRegistry;

import java.util.List;

/**
 * RASP 守卫 - ASM 注入代码的回调入口
 * 
 * 这是 ASM 字节码增强后，注入到业务代码中的检测入口类。
 * 所有被 Hook 的方法在执行前都会调用此类的静态方法。
 * 
 * 为什么用静态方法：
 * 1. JVM 字节码中调用静态方法比实例方法更简单
 * 2. 不需要先创建对象，减少字节码指令
 * 3. 类由 BootstrapClassLoader 加载，需要能全局访问
 * 
 * 性能敏感路径：此方法每次敏感 API 调用都会触发，
 * 需要极快执行（< 5μs 在非检测场景）。
 */
public final class RaspGuard {

    private RaspGuard() {} // 工具类，禁止实例化

    /** 全局 Hook 开关（volatile 保证可见性） */
    private static volatile boolean enabled = false;

    /** Hook 注册中心引用 */
    private static volatile HookRegistry registry;

    /**
     * 初始化（由 Agent Bootstrap 调用）
     */
    public static void init(HookRegistry hookRegistry) {
        registry = hookRegistry;
        enabled = true;
    }

    /**
     * 快速检测开关（ASM 注入的第一步检查）
     * 
     * 在进入 onMethodEnter 之前调用，如果返回 false 则跳过所有检测逻辑。
     * 这个检查非常轻量（一次 volatile 读取），避免在非检测模式下浪费 CPU。
     */
    public static boolean shouldCheck() {
        return enabled;
    }

    /**
     * 方法入口检测回调（由 ASM 注入代码调用）
     * 
     * @param className 被 Hook 的类全限定名
     * @param methodName 被 Hook 的方法名
     * @param methodDesc 方法描述符
     * @param arguments 方法参数数组
     * @param targetObject 调用目标对象（this）
     * @return 0=放行, 1=告警, 2=阻断
     */
    public static int onMethodEnter(String className, String methodName,
                                     String methodDesc, Object[] arguments,
                                     Object targetObject) {
        if (!enabled || registry == null) {
            return 0; // ALLOW
        }

        // 快速路径：获取当前请求上下文
        RaspContext context = RaspContext.get();

        // 如果不是请求线程，且没有全局检测的 Hook，直接放行
        // 这个快速路径对性能至关重要
        if (context == null) {
            return quickCheck(className, methodName, arguments);
        }

        // 如果当前请求上下文禁用了检测，直接放行
        if (!context.isDetectionEnabled()) {
            return 0;
        }

        // 构造 HookEvent
        HookEvent event = new HookEvent(className, methodName, methodDesc, arguments, targetObject);

        // 记录到请求上下文（用于回溯分析）
        context.addHookEvent(event);

        // 查找并执行 Hook 点
        String internalName = className.replace('.', '/');
        List<HookPoint> hookPoints = registry.getHookPoints(internalName);
        if (hookPoints == null || hookPoints.isEmpty()) {
            return 0;
        }

        for (HookPoint hookPoint : hookPoints) {
            if (!hookPoint.isEnabled()) {
                continue;
            }

            DetectResult result = hookPoint.execute(event);
            if (result == null || result.isPass()) {
                continue;
            }

            // 记录告警事件
            if (result.isBlock() || result.isAlert()) {
                AlarmEvent alarm = AlarmEvent.builder()
                    .attackType(result.getAttackType())
                    .severity(result.getSeverity())
                    .action(result.isBlock() ? "BLOCK" : "ALERT")
                    .message(result.getMessage())
                    .evidence(result.getEvidence())
                    .hookClassName(className)
                    .hookMethodName(methodName)
                    .hookArguments(event.getArgumentsString())
                    .requestUri(context.getRequestUri())
                    .remoteAddr(context.getRemoteAddr())
                    .stackTrace(event.getStackTraceString())
                    .build();

                // 缓存告警（异步上报）
                context.addAlarm(alarm);
            }

            // 阻断或告警
            if (result.isBlock()) {
                return 2; // BLOCK
            }
            if (result.isAlert()) {
                return 1; // ALERT (仅记录，不阻断)
            }
        }

        return 0; // ALLOW
    }

    /**
     * 快速检查（非请求线程场景）
     * 
     * 对于配置了全局检测的 Hook 类型（如命令执行、JNDI），
     * 即使在非请求线程中也进行检测。
     * 这是防止线程转移绕过的关键措施。
     */
    private static int quickCheck(String className, String methodName, Object[] arguments) {
        // 命令执行、JNDI 等全局检测类型：
        // 这里做轻量级检查，主要拦截反弹 Shell、JNDI 远程加载等
        String internalName = className.replace('.', '/');
        List<HookPoint> hooks = registry.getHookPoints(internalName);
        if (hooks == null || hooks.isEmpty()) {
            return 0;
        }

        for (HookPoint hook : hooks) {
            if (!hook.isEnabled()) continue;

            HookEvent event = new HookEvent(className, methodName, null, arguments, null);
            DetectResult result = hook.execute(event);

            if (result != null && result.isBlock()) {
                return 2;
            }
        }

        return 0;
    }

    /**
     * 更新 Hook 开关状态（支持热关闭/开启）
     */
    public static void setEnabled(boolean flag) {
        enabled = flag;
    }

    public static boolean isEnabled() {
        return enabled;
    }
}
