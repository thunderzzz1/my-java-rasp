package com.rasp.agent;

import com.rasp.agent.bootstrap.AgentBootstrap;

import java.lang.instrument.Instrumentation;

/**
 * RASP Agentmain 入口 - 支持动态 Attach
 * 
 * 在 JVM 已运行时通过 Attach API 动态加载 Agent，
 * 无需重启应用。
 * 
 * 使用方式：
 * 1. 找到目标 JVM PID: jps -l
 * 2. 注入 Agent:
 *    java -jar rasp-attach.jar --pid <PID> --agent rasp-agent.jar
 * 或通过 JVM 命令:
 *    jcmd <PID> loadAgent /path/to/rasp-agent.jar
 */
public class RaspAgentMain {

    /**
     * 运行时动态 Attach 入口
     * 
     * @param agentArgs 传递给 Agent 的参数
     * @param inst      Instrumentation 实例
     */
    public static void agentmain(String agentArgs, Instrumentation inst) {
        System.out.println("[RASP Agent v" + RaspPremain.VERSION + "] Attaching to running JVM...");

        try {
            AgentBootstrap bootstrap = new AgentBootstrap(agentArgs, inst);
            bootstrap.init();
            bootstrap.addToBootstrapClassLoader();

            // 注册 Transformer（支持 redefinition 和 retransformation）
            RaspPremain.RaspClassFileTransformer transformer = new RaspPremain.RaspClassFileTransformer();
            inst.addTransformer(transformer, true);

            // 对已加载的类进行 retransform
            bootstrap.retransformLoadedClasses(inst, transformer);

            // 开启全局 Hook 开关
            com.rasp.hooks.RaspGuard.setEnabled(true);
            com.rasp.core.hook.HookRegistry.getInstance().setGlobalHookEnabled(true);

            System.out.println("[RASP Agent] Successfully attached to JVM");

        } catch (Exception e) {
            System.err.println("[RASP Agent] Failed to attach: " + e.getMessage());
            e.printStackTrace(System.err);
        }
    }
}
