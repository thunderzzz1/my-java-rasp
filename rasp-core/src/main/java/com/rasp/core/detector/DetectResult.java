package com.rasp.core.detector;

import com.rasp.commons.AttackType;
import com.rasp.commons.Severity;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * 检测结果
 * 
 * 由检测器返回，告知 Hook 回调应该如何处理当前调用。
 * 包含动作（放行/阻断/告警）、攻击类型、严重程度和证据信息。
 */
public class DetectResult {

    /** 预定义的放行结果（全局单例） */
    public static final DetectResult PASS = new DetectResult(Action.PASS, null, Severity.INFO, null, null);

    /** 处理动作 */
    public enum Action {
        PASS,   // 放行
        BLOCK,  // 阻断
        ALERT   // 仅告警（不阻断）
    }

    private final Action action;
    private final AttackType attackType;
    private final Severity severity;
    private final String message;
    private final Map<String, Object> evidence;

    public DetectResult(Action action, AttackType attackType, Severity severity,
                        String message, Map<String, Object> evidence) {
        this.action = action;
        this.attackType = attackType;
        this.severity = severity;
        this.message = message;
        this.evidence = evidence != null ? new HashMap<>(evidence) : new HashMap<>();
    }

    /**
     * 创建阻断结果
     */
    public static DetectResult block(AttackType attackType, Severity severity,
                                      String message, Map<String, Object> evidence) {
        return new DetectResult(Action.BLOCK, attackType, severity, message, evidence);
    }

    /**
     * 创建告警结果（仅记录不阻断）
     */
    public static DetectResult alert(AttackType attackType, Severity severity,
                                      String message, Map<String, Object> evidence) {
        return new DetectResult(Action.ALERT, attackType, severity, message, evidence);
    }

    // --- Getters ---

    public Action getAction() { return action; }
    public AttackType getAttackType() { return attackType; }
    public Severity getSeverity() { return severity; }
    public String getMessage() { return message; }
    public Map<String, Object> getEvidence() { return Collections.unmodifiableMap(evidence); }

    public boolean isBlock() { return action == Action.BLOCK; }
    public boolean isPass() { return action == Action.PASS; }
    public boolean isAlert() { return action == Action.ALERT; }

    @Override
    public String toString() {
        return "DetectResult{" + action + ", " + attackType + ", " + severity + ", " + message + "}";
    }
}
