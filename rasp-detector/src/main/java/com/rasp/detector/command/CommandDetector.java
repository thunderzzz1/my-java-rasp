package com.rasp.detector.command;

import com.rasp.commons.AttackType;
import com.rasp.commons.Severity;
import com.rasp.core.context.HookEvent;
import com.rasp.core.context.RaspContext;
import com.rasp.core.detector.DetectResult;
import com.rasp.detector.AbstractDetector;

import java.util.*;
import java.util.regex.Pattern;

/**
 * 命令执行检测器
 * 
 * 检测操作系统命令注入攻击，包括：
 * 1. 命令拼接注入（管道、分号、逻辑运算符）
 * 2. 反弹 Shell
 * 3. 文件下载执行（curl/wget + pipe）
 * 
 * 该检测器全局开启（不限于 HTTP 请求线程），
 * 因为命令执行可能是定时任务、后台线程触发的。
 */
public class CommandDetector extends AbstractDetector {

    /** 命令分隔符和注入操作符 */
    private static final Pattern CMD_SEPARATOR = Pattern.compile(
        "[;|&`$(){}\\[\\]<>\\n\\r]"
    );

    /** 反弹 Shell 特征 */
    private static final Pattern REVERSE_SHELL = Pattern.compile(
        "(?i)(/dev/tcp/|/dev/udp/|bash\\s+-i|nc\\s+.*-e|python\\s+-c.*socket)"
    );

    /** 文件下载执行特征 */
    private static final Pattern DOWNLOAD_EXEC = Pattern.compile(
        "(?i)(curl|wget)\\s+.*\\|\\s*(bash|sh|python|perl|ruby)"
    );

    /** 常见系统命令白名单（可信命令，不检测） */
    private static final Set<String> TRUSTED_COMMANDS = new HashSet<>(Arrays.asList(
        "ping", "nslookup", "host", "dig", "traceroute", "netstat",
        "ifconfig", "ipconfig", "whoami", "id", "uname", "hostname",
        "java", "node", "python", "ruby", "perl",
        "ls", "dir", "cat", "head", "tail", "grep", "find", "echo"
    ));

    public CommandDetector() {
        super(AttackType.COMMAND_INJECTION, "command-detector");
    }

    @Override
    protected boolean isGlobalDetect() {
        return true; // 命令执行需要全局检测
    }

    @Override
    protected DetectResult doDetect(HookEvent event, RaspContext context) {
        // ProcessBuilder.start() 的参数是 command 列表
        // Runtime.exec() 的参数是命令字符串
        String fullCommand = extractCommand(event);
        if (fullCommand == null || fullCommand.isEmpty()) {
            return DetectResult.PASS;
        }

        // 1. 反弹 Shell 检测（最高优先级）
        if (REVERSE_SHELL.matcher(fullCommand).find()) {
            return block(Severity.HIGH,
                "Reverse shell detected: " + truncate(fullCommand));
        }

        // 2. 下载执行检测
        if (DOWNLOAD_EXEC.matcher(fullCommand).find()) {
            return block(Severity.HIGH,
                "Download-and-execute pattern detected: " + truncate(fullCommand));
        }

        // 3. 命令分隔符检测（管道、分号等）
        if (CMD_SEPARATOR.matcher(fullCommand).find()) {
            // 有 context → 参数关联分析
            if (context != null && context.isParamTainted(fullCommand)) {
                return block(Severity.HIGH,
                    "Command injection: request parameter value found in command: "
                        + truncate(fullCommand));
            }
            // 或无 context 但仍检测到分隔符 → 告警
            if (context == null) {
                return block(Severity.HIGH,
                    "Command injection: suspicious separator in command: "
                        + truncate(fullCommand));
            }
        }

        // 4. 命令白名单检查
        if (isTrustedCommand(fullCommand)) {
            return DetectResult.PASS;
        }

        // 5. 参数关联分析
        if (context != null && context.isParamTainted(fullCommand)) {
            return block(Severity.HIGH,
                "Suspicious command with tainted parameter: " + truncate(fullCommand));
        }

        return DetectResult.PASS;
    }

    /**
     * 从 Hook 事件中提取命令字符串
     */
    private String extractCommand(HookEvent event) {
        Object arg0 = event.getArgument(0);
        if (arg0 instanceof String) {
            return (String) arg0; // Runtime.exec(String)
        }
        if (arg0 instanceof String[]) {
            return String.join(" ", (String[]) arg0); // Runtime.exec(String[])
        }
        if (arg0 instanceof List) {
            List<?> list = (List<?>) arg0;
            StringBuilder sb = new StringBuilder();
            for (Object item : list) {
                if (item != null) {
                    if (sb.length() > 0) sb.append(" ");
                    sb.append(item.toString());
                }
            }
            return sb.toString(); // ProcessBuilder.command
        }
        return null;
    }

    /**
     * 检查是否是可信命令（白名单）
     * 可信命令定义为：命令本身在白名单中 + 不包含命令分隔符
     */
    private boolean isTrustedCommand(String command) {
        // 提取第一个命令（去掉参数）
        String trimmed = command.trim();
        int spaceIdx = trimmed.indexOf(' ');
        String cmd = spaceIdx > 0 ? trimmed.substring(0, spaceIdx) : trimmed;

        // 提取命令名（去掉路径，如 /bin/ls → ls）
        int lastSlash = cmd.lastIndexOf('/');
        cmd = lastSlash >= 0 ? cmd.substring(lastSlash + 1) : cmd;
        int lastBackslash = cmd.lastIndexOf('\\');
        cmd = lastBackslash >= 0 ? cmd.substring(lastBackslash + 1) : cmd;

        return TRUSTED_COMMANDS.contains(cmd.toLowerCase());
    }

    private String truncate(String s) {
        return s.length() > 200 ? s.substring(0, 200) + "..." : s;
    }
}
