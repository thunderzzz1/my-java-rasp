package com.rasp.core.context;

/**
 * Hook 触发事件
 * 
 * 当 ASM 注入的 Hook 代码被触发时，记录该事件的完整信息，
 * 包括触发位置、方法参数、调用时间等。
 * 
 * 设计为轻量级对象，使用对象池避免频繁 GC（高 QPS 场景下优化）。
 */
public class HookEvent {

    /** 被 Hook 的类全限定名 */
    private final String className;

    /** 被 Hook 的方法名 */
    private final String methodName;

    /** 方法签名描述符 */
    private final String methodDesc;

    /** 方法参数数组 */
    private final Object[] arguments;

    /** Hook 触发时间（纳秒） */
    private final long triggerTimeNanos;

    /** 调用目标对象（this），可能为 null（静态方法） */
    private final Object targetObject;

    /** 调用栈快照（可按需生成） */
    private volatile StackTraceElement[] stackTrace;

    public HookEvent(String className, String methodName, String methodDesc,
                     Object[] arguments, Object targetObject) {
        this.className = className;
        this.methodName = methodName;
        this.methodDesc = methodDesc;
        this.arguments = arguments != null ? arguments.clone() : new Object[0];
        this.triggerTimeNanos = System.nanoTime();
        this.targetObject = targetObject;
    }

    public String getClassName() { return className; }
    public String getMethodName() { return methodName; }
    public String getMethodDesc() { return methodDesc; }
    public long getTriggerTimeNanos() { return triggerTimeNanos; }
    public Object getTargetObject() { return targetObject; }

    /**
     * 获取第 N 个参数
     */
    public Object getArgument(int index) {
        if (index >= 0 && index < arguments.length) {
            return arguments[index];
        }
        return null;
    }

    /**
     * 获取所有参数的字符串形式（用于告警证据）
     */
    public String getArgumentsString() {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < arguments.length; i++) {
            if (i > 0) sb.append(", ");
            Object arg = arguments[i];
            if (arg == null) {
                sb.append("null");
            } else if (arg instanceof String) {
                String s = (String) arg;
                sb.append("\"").append(s.length() > 200 ? s.substring(0, 200) + "..." : s).append("\"");
            } else {
                sb.append(arg.getClass().getSimpleName());
            }
        }
        sb.append("]");
        return sb.toString();
    }

    /**
     * 获取调用栈（懒加载，只在告警时生成）
     */
    public StackTraceElement[] getStackTrace() {
        if (stackTrace == null) {
            stackTrace = Thread.currentThread().getStackTrace();
        }
        return stackTrace;
    }

    /**
     * 生成调用栈的格式化字符串
     */
    public String getStackTraceString() {
        StackTraceElement[] trace = getStackTrace();
        StringBuilder sb = new StringBuilder();
        int count = 0;
        for (StackTraceElement element : trace) {
            String className = element.getClassName();
            // 跳过 RASP 自身的调用栈
            if (className.startsWith("com.rasp.") || className.startsWith("java.lang.Thread")) {
                continue;
            }
            sb.append("    at ").append(element.toString()).append("\n");
            count++;
            if (count >= 30) { // 最多30帧
                sb.append("    ... [truncated]\n");
                break;
            }
        }
        return sb.toString();
    }

    @Override
    public String toString() {
        return "HookEvent{" + className + "." + methodName + methodDesc + "}";
    }
}
