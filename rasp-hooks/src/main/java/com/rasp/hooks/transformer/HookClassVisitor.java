package com.rasp.hooks.transformer;

import com.rasp.core.hook.HookPoint;
import org.objectweb.asm.*;

import java.util.List;

/**
 * ASM ClassVisitor - 对目标类进行字节码增强
 * 
 * 遍历目标类的所有方法，对匹配 HookPoint 的方法进行插桩。
 * 每个被匹配的方法会创建一个 RaspMethodAdapter 来注入检测代码。
 */
public class HookClassVisitor extends ClassVisitor {

    private final String className;
    private final List<HookPoint> hookPoints;
    private String internalClassName;

    public HookClassVisitor(int api, ClassVisitor cv, String className,
                             List<HookPoint> hookPoints) {
        super(api, cv);
        this.className = className;
        this.hookPoints = hookPoints;
    }

    @Override
    public void visit(int version, int access, String name, String signature,
                      String superName, String[] interfaces) {
        this.internalClassName = name;
        super.visit(version, access, name, signature, superName, interfaces);
    }

    @Override
    public MethodVisitor visitMethod(int access, String name, String descriptor,
                                      String signature, String[] exceptions) {
        MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);

        // 跳过特殊方法
        if (isSpecialMethod(name)) {
            return mv;
        }

        // 查找匹配的 Hook 点
        List<HookPoint> matched = findMatchingHooks(name, descriptor);
        if (matched == null || matched.isEmpty()) {
            return mv;
        }

        // 创建 RaspMethodAdapter 进行插桩
        return new RaspMethodAdapter(
            Opcodes.ASM9, mv, access,
            internalClassName, name, descriptor,
            matched
        );
    }

    /**
     * 跳过构造方法、静态初始化块、finalize 等特殊方法
     */
    private boolean isSpecialMethod(String methodName) {
        return "<init>".equals(methodName)      // 构造函数
            || "<clinit>".equals(methodName)    // 静态初始化块
            || "finalize".equals(methodName);    // GC 清理
    }

    /**
     * 查找匹配该方法的 Hook 点列表
     */
    private List<HookPoint> findMatchingHooks(String methodName, String methodDesc) {
        List<HookPoint> matched = new java.util.ArrayList<>(hookPoints.size());
        for (HookPoint hp : hookPoints) {
            if (hp.getMethodName().equals(methodName)) {
                // 如果 HookPoint 指定了方法描述符，需要精确匹配
                if (hp.getMethodDesc() == null || hp.getMethodDesc().equals(methodDesc)) {
                    matched.add(hp);
                }
            }
        }
        return matched.isEmpty() ? null : matched;
    }
}
