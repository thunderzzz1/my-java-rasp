package com.rasp.core.hook;

/**
 * Hook 执行结果
 * 
 * 由检测器返回，告知 JVM 应该对当前调用采取什么动作。
 * 这是 RASP 从"观察"变为"控制"的关键接口。
 */
public class HookResult {

    /**
     * 放行 - 允许操作继续执行。
     * 全局单例，避免频繁创建对象。
     */
    public static final HookResult ALLOW = new HookResult(Action.ALLOW, null, null);

    /**
     * 处理动作
     */
    public enum Action {
        /** 放行，不做任何干预 */
        ALLOW,

        /** 阻断，抛出 SecurityException */
        BLOCK,

        /** 仅告警不阻断（旁路模式） */
        ALERT
    }

    private final Action action;
    private final String message;
    private final Throwable exception;

    public HookResult(Action action, String message, Throwable exception) {
        this.action = action;
        this.message = message;
        this.exception = exception;
    }

    /**
     * 创建阻断结果
     */
    public static HookResult block(String message) {
        return new HookResult(Action.BLOCK, message,
                new SecurityException("RASP: " + message));
    }

    /**
     * 创建告警结果（仅记录不阻断）
     */
    public static HookResult alert(String message) {
        return new HookResult(Action.ALERT, message, null);
    }

    // --- Getters ---

    public Action getAction() { return action; }
    public String getMessage() { return message; }
    public Throwable getException() { return exception; }

    public boolean isBlocked() { return action == Action.BLOCK; }
    public boolean isAllowed() { return action == Action.ALLOW; }
    public boolean isAlert() { return action == Action.ALERT; }

    @Override
    public String toString() {
        return "HookResult{" + action + ", " + message + "}";
    }
}
