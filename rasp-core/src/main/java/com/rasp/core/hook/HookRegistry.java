package com.rasp.core.hook;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Hook 注册中心
 * 
 * 管理所有 HookPoint 的注册、查找和生命周期。
 * 是整个 RASP 系统的"神经中枢"——Transformer 从这里获取 Hook 点，
 * 检测器通过这里注册回调。
 * 
 * 设计特点：
 * 1. 以 className 为索引的高效查找（HashMap）
 * 2. 支持运行时动态添加/移除 Hook（CopyOnWriteArrayList 保证并发安全）
 * 3. 支持多 Hook 对同一类/同一方法的组合
 */
public class HookRegistry {

    /** className (internal format) → List<HookPoint> */
    private final Map<String, List<HookPoint>> hookIndex;

    /** 所有注册的 Hook 点（用于遍历） */
    private final List<HookPoint> allHooks;

    /** 需要 Hook 的类名集合（ASM 内部格式），用于 ClassFileTransformer 快速过滤 */
    private final Set<String> hookTargetClasses;

    /** 全局 Hook 开关 */
    private volatile boolean globalHookEnabled = false;

    private static final HookRegistry INSTANCE = new HookRegistry();

    public static HookRegistry getInstance() {
        return INSTANCE;
    }

    private HookRegistry() {
        this.hookIndex = new ConcurrentHashMap<>(64);
        this.allHooks = new CopyOnWriteArrayList<>();
        this.hookTargetClasses = Collections.newSetFromMap(new ConcurrentHashMap<>(128));
    }

    /**
     * 注册一个 Hook 点
     */
    public void register(HookPoint hookPoint) {
        String internalName = hookPoint.getInternalClassName();

        hookIndex.computeIfAbsent(internalName, k -> new CopyOnWriteArrayList<>())
                .add(hookPoint);

        // 按优先级排序
        hookIndex.get(internalName).sort(Comparator.comparingInt(HookPoint::getPriority));

        allHooks.add(hookPoint);
        hookTargetClasses.add(internalName);
    }

    /**
     * 批量注册 Hook 点
     */
    public void registerAll(Collection<HookPoint> hookPoints) {
        for (HookPoint hp : hookPoints) {
            register(hp);
        }
    }

    /**
     * 移除一个 Hook 点
     */
    public void unregister(HookPoint hookPoint) {
        List<HookPoint> hooks = hookIndex.get(hookPoint.getInternalClassName());
        if (hooks != null) {
            hooks.remove(hookPoint);
            if (hooks.isEmpty()) {
                hookIndex.remove(hookPoint.getInternalClassName());
                hookTargetClasses.remove(hookPoint.getInternalClassName());
            }
        }
        allHooks.remove(hookPoint);
    }

    /**
     * 获取某个类的所有 Hook 点
     * 
     * @param internalClassName ASM 内部格式的类名（java/lang/ProcessBuilder）
     * @return Hook 点列表，可能为空
     */
    public List<HookPoint> getHookPoints(String internalClassName) {
        List<HookPoint> hooks = hookIndex.get(internalClassName);
        return hooks != null ? hooks : Collections.emptyList();
    }

    /**
     * 判断某个类是否需要 Hook（快速过滤，O(1)）
     */
    public boolean isHookTarget(String internalClassName) {
        return hookTargetClasses.contains(internalClassName);
    }

    /**
     * 获取所有 Hook 点
     */
    public List<HookPoint> getAllHooks() {
        return Collections.unmodifiableList(allHooks);
    }

    /**
     * 获取需要 Hook 的类名集合
     */
    public Set<String> getHookTargetClasses() {
        return Collections.unmodifiableSet(hookTargetClasses);
    }

    /**
     * 获取已注册的 Hook 总数
     */
    public int getHookCount() {
        return allHooks.size();
    }

    // ===== 全局开关 =====

    public boolean isGlobalHookEnabled() {
        return globalHookEnabled;
    }

    /**
     * 开启全局 Hook 开关
     * Agent 启动初期关闭此开关，初始化完成后再打开
     */
    public void setGlobalHookEnabled(boolean globalHookEnabled) {
        this.globalHookEnabled = globalHookEnabled;
    }

    /**
     * 清空所有注册（用于热更新时重新加载）
     */
    public void clear() {
        hookIndex.clear();
        allHooks.clear();
        hookTargetClasses.clear();
    }
}
