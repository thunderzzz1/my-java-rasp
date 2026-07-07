package com.rasp.detector.file;

import com.rasp.commons.AttackType;
import com.rasp.commons.Severity;
import com.rasp.core.context.HookEvent;
import com.rasp.core.context.RaspContext;
import com.rasp.core.detector.DetectResult;
import com.rasp.detector.AbstractDetector;

import java.util.*;

/**
 * 文件操作检测器
 * 
 * 检测路径遍历、敏感文件访问、WebShell 写入等文件层攻击。
 * Hook FileInputStream/FileOutputStream/Files.* 等文件 API。
 */
public class FileDetector extends AbstractDetector {

    /** 路径遍历模式 */
    private static final String[] TRAVERSAL_PATTERNS = {"../", "..\\"};

    /** 敏感文件路径（Linux） */
    private static final Set<String> SENSITIVE_FILES = new HashSet<>(Arrays.asList(
        "/etc/passwd", "/etc/shadow", "/etc/hosts",
        "/root/.ssh/id_rsa", "/root/.bash_history",
        "/proc/self/environ", "/proc/self/cmdline",
        "/var/log/", "/tmp/"
    ));

    /** WebShell 文件后缀（写入时检测） */
    private static final Set<String> WEBSHELL_EXTENSIONS = new HashSet<>(Arrays.asList(
        ".jsp", ".jspx", ".php", ".phtml", ".asp", ".aspx", ".ashx"
    ));

    public FileDetector() {
        super(AttackType.FILE_OPERATION, "file-detector");
    }

    @Override
    protected DetectResult doDetect(HookEvent event, RaspContext context) {
        String filePath = extractFilePath(event);
        if (filePath == null || filePath.isEmpty()) {
            return DetectResult.PASS;
        }

        boolean isWrite = isWriteOperation(event);
        filePath = normalizePath(filePath);

        // 1. 路径遍历检测
        for (String pattern : TRAVERSAL_PATTERNS) {
            if (filePath.contains(pattern)) {
                return DetectResult.block(AttackType.FILE_OPERATION, Severity.HIGH,
                    "Path traversal detected: " + filePath,
                    Collections.singletonMap("file_path", filePath));
            }
        }

        // 2. 敏感文件读取检测
        if (!isWrite) {
            for (String sensitive : SENSITIVE_FILES) {
                if (filePath.startsWith(sensitive)) {
                    return DetectResult.block(AttackType.FILE_OPERATION, Severity.HIGH,
                        "Accessing sensitive file: " + filePath,
                        Collections.singletonMap("file_path", filePath));
                }
            }
        }

        // 3. WebShell 写入检测
        if (isWrite) {
            String lower = filePath.toLowerCase();
            for (String ext : WEBSHELL_EXTENSIONS) {
                if (lower.endsWith(ext)) {
                    return DetectResult.block(AttackType.WEBSHELL, Severity.HIGH,
                        "WebShell file write detected: " + filePath,
                        Collections.singletonMap("file_path", filePath));
                }
            }
        }

        // 4. 参数关联
        if (context != null && context.isParamTainted(filePath)) {
            return DetectResult.block(AttackType.FILE_OPERATION, Severity.HIGH,
                "File path controlled by user input: " + filePath,
                Collections.singletonMap("file_path", filePath));
        }

        return DetectResult.PASS;
    }

    private String extractFilePath(HookEvent event) {
        Object arg = event.getArgument(0);
        if (arg instanceof String) return (String) arg;
        if (arg instanceof java.io.File) return ((java.io.File) arg).getPath();
        if (arg instanceof java.nio.file.Path) return arg.toString();
        return null;
    }

    private boolean isWriteOperation(HookEvent event) {
        String method = event.getMethodName();
        String cls = event.getClassName();
        return method.contains("write") || method.contains("output")
            || cls.contains("FileOutputStream") || cls.contains("output");
    }

    private String normalizePath(String path) {
        return path.replace('\\', '/');
    }
}
