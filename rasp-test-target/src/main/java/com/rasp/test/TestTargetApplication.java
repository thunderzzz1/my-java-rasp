package com.rasp.test;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * RASP Test Target - 包含各类漏洞的测试靶场应用
 * 
 * 启动方式:
 *   java -javaagent:../rasp-agent/target/rasp-agent-1.0.0-SNAPSHOT.jar -jar rasp-test-target.jar
 * 
 * 漏洞端点:
 * - /attack/sql/raw          SQL拼接注入
 * - /attack/sql/statement    Statement注入
 * - /attack/cmd/exec         Runtime.exec注入
 * - /attack/cmd/process      ProcessBuilder注入
 * - /attack/deser/base64     Base64反序列化
 * - /attack/file/read        路径遍历读文件
 * - /attack/file/write       任意文件写入
 * - /attack/ssrf/get         SSRF请求
 * - /attack/jndi/lookup      JNDI注入
 */
@SpringBootApplication
public class TestTargetApplication {
    public static void main(String[] args) {
        SpringApplication.run(TestTargetApplication.class, args);
    }
}
