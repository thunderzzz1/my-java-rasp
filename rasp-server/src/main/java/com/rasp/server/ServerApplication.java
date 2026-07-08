package com.rasp.server;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * RASP 管理后台主应用
 * 
 * 功能:
 * - 攻击告警管理 (CRUD + 统计)
 * - Agent 健康监控
 * - 攻击大盘 & 趋势图
 * - 数据库: H2(开发) / MySQL(生产)
 */
@SpringBootApplication
@EnableScheduling
public class ServerApplication {
    public static void main(String[] args) {
        SpringApplication.run(ServerApplication.class, args);
    }
}
