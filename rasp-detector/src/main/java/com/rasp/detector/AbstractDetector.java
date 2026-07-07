package com.rasp.detector;

import com.rasp.commons.AttackType;
import com.rasp.commons.Severity;
import com.rasp.core.context.HookEvent;
import com.rasp.core.context.RaspContext;
import com.rasp.core.detector.DetectResult;

/**
 * 检测器抽象基类
 * 
 * 模板方法模式：
 * 所有检测器遵循 preCheck → doDetect → postDetect 的统一流程，
 * 子类只需实现 doDetect 即可。
 */
public abstract class AbstractDetector {

    private final AttackType attackType;
    private final String name;

    protected AbstractDetector(AttackType attackType, String name) {
        this.attackType = attackType;
        this.name = name;
    }

    /**
     * 检测入口（模板方法）
     */
    public final DetectResult detect(HookEvent event, RaspContext context) {
        // 1. 快速过滤
        if (!preCheck(event, context)) {
            return DetectResult.PASS;
        }

        // 2. 核心检测
        DetectResult result;
        try {
            result = doDetect(event, context);
        } catch (Exception e) {
            // 检测器异常不阻塞业务
            return DetectResult.PASS;
        }

        if (result == null) {
            return DetectResult.PASS;
        }

        // 3. 后处理（统计等）
        postDetect(event, context, result);

        return result;
    }

    /**
     * 快速过滤：是否需要本次检测？
     */
    protected boolean preCheck(HookEvent event, RaspContext context) {
        // 默认允许所有检测，各检测器内部自行处理 context 为 null 的情况
        return true;
    }

    /**
     * 核心检测逻辑（子类实现）
     */
    protected abstract DetectResult doDetect(HookEvent event, RaspContext context);

    /**
     * 后处理（默认空实现）
     */
    protected void postDetect(HookEvent event, RaspContext context, DetectResult result) {
        // 子类可覆盖：更新统计、记录日志等
    }

    /**
     * 是否需要全局检测（即使不在请求线程中）
     * 命令执行、内存马检测等需要全局开启
     */
    protected boolean isGlobalDetect() {
        return false;
    }

    public AttackType getAttackType() { return attackType; }
    public String getName() { return name; }

    /**
     * 便捷方法：构造阻断结果
     */
    protected DetectResult block(Severity severity, String message) {
        return DetectResult.block(attackType, severity, message, null);
    }

    protected DetectResult alert(Severity severity, String message) {
        return DetectResult.alert(attackType, severity, message, null);
    }
}
