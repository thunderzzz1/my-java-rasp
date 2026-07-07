package com.rasp.core.hook;

import com.rasp.core.context.HookEvent;
import com.rasp.core.detector.DetectResult;

/**
 * Hook 点定义
 * 
 * 描述一个需要 Hook 的类和方法，以及对应的检测器回调。
 * 注册到 HookRegistry 后，Agent 会在类加载时自动对该方法插桩。
 */
public class HookPoint {

    /** 目标类全限定名（如 java.lang.ProcessBuilder） */
    private final String className;

    /** 目标方法名（如 start） */
    private final String methodName;

    /** 方法描述符（如 ()Ljava/lang/Process;），null 表示匹配所有重载 */
    private final String methodDesc;

    /** Hook 类型 */
    private final HookType hookType;

    /** 优先级（越小越高，同类的多个 Hook 按优先级排序） */
    private final int priority;

    /** 是否启用 */
    private volatile boolean enabled;

    /** Hook 回调接口 */
    private final HookHandler handler;

    private HookPoint(Builder builder) {
        this.className = builder.className;
        this.methodName = builder.methodName;
        this.methodDesc = builder.methodDesc;
        this.hookType = builder.hookType != null ? builder.hookType : HookType.BEFORE;
        this.priority = builder.priority;
        this.enabled = builder.enabled;
        this.handler = builder.handler;
    }

    // --- Getters ---

    public String getClassName() { return className; }
    public String getMethodName() { return methodName; }
    public String getMethodDesc() { return methodDesc; }
    public HookType getHookType() { return hookType; }
    public int getPriority() { return priority; }
    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    /**
     * 执行 Hook 回调
     * 
     * @param event Hook 事件（包含类名、方法名、参数等信息）
     * @return 检测结果
     */
    public DetectResult execute(HookEvent event) {
        if (!enabled || handler == null) {
            return null;
        }
        try {
            return handler.onHook(event);
        } catch (Exception e) {
            // Hook 回调本身不能抛异常影响业务
            return null;
        }
    }

    /**
     * 获取 ASM 内部类名（java/lang/ProcessBuilder 格式）
     */
    public String getInternalClassName() {
        return className.replace('.', '/');
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof HookPoint)) return false;
        HookPoint that = (HookPoint) o;
        return className.equals(that.className)
                && methodName.equals(that.methodName);
    }

    @Override
    public int hashCode() {
        return 31 * className.hashCode() + methodName.hashCode();
    }

    @Override
    public String toString() {
        return "HookPoint{" + className + "." + methodName + methodDesc + "}";
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private String className;
        private String methodName;
        private String methodDesc;
        private HookType hookType = HookType.BEFORE;
        private int priority = 100;
        private boolean enabled = true;
        private HookHandler handler;

        public Builder className(String className) { this.className = className; return this; }
        public Builder methodName(String methodName) { this.methodName = methodName; return this; }
        public Builder methodDesc(String methodDesc) { this.methodDesc = methodDesc; return this; }
        public Builder hookType(HookType hookType) { this.hookType = hookType; return this; }
        public Builder priority(int priority) { this.priority = priority; return this; }
        public Builder enabled(boolean enabled) { this.enabled = enabled; return this; }
        public Builder handler(HookHandler handler) { this.handler = handler; return this; }
        public HookPoint build() {
            if (className == null) throw new IllegalArgumentException("className is required");
            if (methodName == null) throw new IllegalArgumentException("methodName is required");
            return new HookPoint(this);
        }
    }

    /**
     * Hook 回调接口
     */
    @FunctionalInterface
    public interface HookHandler {
        /**
         * 当 Hook 被触发时调用
         * 
         * @param event Hook 事件
         * @return 检测结果，null 表示放行
         */
        DetectResult onHook(HookEvent event);
    }
}
