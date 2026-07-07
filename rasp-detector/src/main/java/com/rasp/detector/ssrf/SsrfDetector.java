package com.rasp.detector.ssrf;

import com.rasp.commons.AttackType;
import com.rasp.commons.Severity;
import com.rasp.core.context.HookEvent;
import com.rasp.core.context.RaspContext;
import com.rasp.core.detector.DetectResult;
import com.rasp.detector.AbstractDetector;

import java.net.*;
import java.util.*;

/**
 * SSRF 检测器
 * 
 * 检测服务端请求伪造攻击，防止攻击者利用服务器发起内网请求。
 * Hook URL.openConnection() 和 HttpURLConnection.connect()。
 */
public class SsrfDetector extends AbstractDetector {

    /** 危险协议 */
    private static final Set<String> DANGEROUS_PROTOCOLS = new HashSet<>(Arrays.asList(
        "file", "gopher", "jar", "netdoc", "ftp", "dict", "ldap", "rmi"
    ));

    /** 内网 IP 段 */
    private static final String[] PRIVATE_RANGES = {
        "10.", "172.16.", "172.17.", "172.18.", "172.19.",
        "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
        "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
        "172.30.", "172.31.", "192.168.", "127.", "0.0.0.0"
    };

    /** 云 Metadata 地址 */
    private static final String[] CLOUD_METADATA = {
        "169.254.169.254", "100.100.100.200", "metadata.google.internal"
    };

    public SsrfDetector() {
        super(AttackType.SSRF, "ssrf-detector");
    }

    @Override
    protected DetectResult doDetect(HookEvent event, RaspContext context) {
        String urlStr = extractUrl(event);
        if (urlStr == null || urlStr.isEmpty()) {
            return DetectResult.PASS;
        }

        URL url;
        try {
            url = new URL(urlStr);
        } catch (Exception e) {
            return DetectResult.PASS;
        }

        String protocol = url.getProtocol().toLowerCase();
        String host = url.getHost();

        // 1. 危险协议检测
        if (DANGEROUS_PROTOCOLS.contains(protocol)) {
            return DetectResult.block(AttackType.SSRF, Severity.HIGH,
                "Dangerous protocol in SSRF: " + protocol + "://" + host,
                Map.of("url", urlStr, "protocol", protocol));
        }

        // 2. 内网 IP 检测
        if (isPrivateAddress(host)) {
            return DetectResult.block(AttackType.SSRF, Severity.HIGH,
                "SSRF to internal network: " + host,
                Map.of("url", urlStr, "host", host));
        }

        // 3. 云 Metadata 检测
        for (String meta : CLOUD_METADATA) {
            if (host.equals(meta) || host.contains(meta)) {
                return DetectResult.block(AttackType.SSRF, Severity.HIGH,
                    "SSRF to cloud metadata service: " + host,
                    Map.of("url", urlStr));
            }
        }

        // 4. 参数关联
        if (context != null && context.isParamTainted(urlStr)) {
            return DetectResult.block(AttackType.SSRF, Severity.HIGH,
                "URL controlled by user input: " + urlStr,
                Map.of("url", urlStr));
        }

        return DetectResult.PASS;
    }

    private String extractUrl(HookEvent event) {
        Object arg = event.getArgument(0);
        if (arg instanceof String) return (String) arg;
        if (arg instanceof URL) return arg.toString();
        if (arg instanceof URLConnection) return ((URLConnection) arg).getURL().toString();
        return null;
    }

    private boolean isPrivateAddress(String host) {
        // 排除正常域名（有多个点的一般是公网域名）
        if (!isIpLike(host) && host.contains(".") && countDots(host) > 1) {
            return false;
        }
        for (String prefix : PRIVATE_RANGES) {
            if (host.startsWith(prefix)) return true;
        }
        return false;
    }

    private boolean isIpLike(String host) {
        return host.matches("\\d+\\.\\d+\\.\\d+\\.\\d+");
    }

    private int countDots(String host) {
        int count = 0;
        for (char c : host.toCharArray()) if (c == '.') count++;
        return count;
    }
}
