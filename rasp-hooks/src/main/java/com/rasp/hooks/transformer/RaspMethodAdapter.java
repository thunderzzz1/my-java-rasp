package com.rasp.hooks.transformer;

import com.rasp.core.hook.HookPoint;
import com.rasp.core.hook.HookRegistry;
import org.objectweb.asm.*;
import org.objectweb.asm.commons.AdviceAdapter;

import java.util.List;

/**
 * ASM MethodVisitor - 在目标方法入口注入 RASP 检测代码
 * 
 * 基于 ASM AdviceAdapter，在方法体最开始处插入检测逻辑。
 * 
 * 注入的伪代码逻辑：
 * <pre>
 * // 原始方法签名: public AnyType anyMethod(ArgType1 arg1, ArgType2 arg2, ...)
 * 
 * // === 注入开始 ===
 * if (com.rasp.hooks.RaspGuard.shouldCheck()) {
 *     // 构建参数数组
 *     Object[] __rasp_args = new Object[]{arg1, arg2, ...};
 *     // 调用检测入口
 *     int __rasp_result = com.rasp.hooks.RaspGuard.onMethodEnter(
 *         "com.example.TargetClass",    // 类名
 *         "targetMethod",                // 方法名
 *         "(ArgType1;ArgType2;)V",      // 方法描述符
 *         __rasp_args,                   // 参数
 *         this                           // 目标对象
 *     );
 *     // 检查结果
 *     if (__rasp_result == 2) { // BLOCK
 *         throw new SecurityException("Blocked by RASP: ...");
 *     }
 * }
 * // === 注入结束 ===
 * 
 * // 原始方法体 ...
 * </pre>
 * 
 * ASM 操作码关键指令：
 * - INVOKESTATIC: 调用静态方法
 * - ANEWARRAY: 创建对象数组
 * - AASTORE: 存储到数组
 * - IFEQ/IFNE: 整数比较跳转
 * - NEW/DUP/INVOKESPECIAL: 创建新对象
 * - ATHROW: 抛出异常
 * - ICONST_0/1/2: 加载整数常量
 */
public class RaspMethodAdapter extends AdviceAdapter {

    private final String className;
    private final String methodName;
    private final String methodDesc;
    private final int access;
    private final Type[] argumentTypes;
    private final Type returnType;
    private final boolean isStatic;

    /** Hook 点配置 */
    private final List<HookPoint> hookPoints;

    /** RASP 守卫类内部名称 */
    private static final String RASP_GUARD = "com/rasp/hooks/RaspGuard";
    private static final String RASP_GUARD_DESC = "Lcom/rasp/hooks/RaspGuard;";

    public RaspMethodAdapter(int api, MethodVisitor mv, int access,
                              String className, String methodName, String methodDesc,
                              List<HookPoint> hookPoints) {
        super(api, mv, access, methodName, methodDesc);
        this.className = className;
        this.methodName = methodName;
        this.methodDesc = methodDesc;
        this.access = access;
        this.argumentTypes = Type.getArgumentTypes(methodDesc);
        this.returnType = Type.getReturnType(methodDesc);
        this.isStatic = (access & Opcodes.ACC_STATIC) != 0;
        this.hookPoints = hookPoints;
    }

    @Override
    protected void onMethodEnter() {
        if (hookPoints == null || hookPoints.isEmpty()) {
            return;
        }

        // 1. 检查 shouldCheck() → 如果 false 则跳过
        Label skipLabel = newLabel();
        mv.visitMethodInsn(INVOKESTATIC, RASP_GUARD, "shouldCheck", "()Z", false);
        mv.visitJumpInsn(IFEQ, skipLabel);

        // 2. 加载类名字符串
        mv.visitLdcInsn(className.replace('/', '.'));

        // 3. 加载方法名字符串
        mv.visitLdcInsn(methodName);

        // 4. 加载方法描述符字符串
        mv.visitLdcInsn(methodDesc);

        // 5. 构建参数数组 Object[]
        int argCount = argumentTypes.length;
        pushInt(argCount);
        mv.visitTypeInsn(ANEWARRAY, "java/lang/Object");

        // 5a. 如果不是静态方法，第一个参数是 this
        int localVarOffset = 0;
        if (!isStatic) {
            mv.visitInsn(DUP);
            pushInt(0);
            mv.visitVarInsn(ALOAD, 0); // this
            boxIfPrimitive(Type.getType(Object.class)); // this 不需要 boxing，但为了一致性
            mv.visitInsn(AASTORE);
            localVarOffset = 1;
        }

        // 5b. 填充方法参数
        for (int i = 0; i < argumentTypes.length; i++) {
            mv.visitInsn(DUP);
            pushInt(isStatic ? i : i + 1); // 索引（非静态方法数组索引从1开始因为0是this...等等，让我重新考虑）

            // 简化：不管 static 还是非 static，都在数组中包含 this
            int argIndex = i;
            int slotIndex = isStatic ? i : i + 1;

            // 加载参数到操作数栈
            loadArg(slotIndex, argumentTypes[i]);

            // 基本类型装箱
            boxIfPrimitive(argumentTypes[i]);

            mv.visitInsn(AASTORE);
        }

        // 6. 加载 targetObject (this 或 null)
        if (isStatic) {
            mv.visitInsn(ACONST_NULL);
        } else {
            mv.visitVarInsn(ALOAD, 0); // this
        }

        // 7. 调用 onMethodEnter()
        mv.visitMethodInsn(INVOKESTATIC, RASP_GUARD, "onMethodEnter",
            "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Object;)I",
            false);

        // 8. 检查返回值: 2 = BLOCK
        Label continueLabel = newLabel();
        mv.visitInsn(ICONST_2); // BLOCK = 2
        mv.visitJumpInsn(IF_ICMPNE, continueLabel);

        // 9. 阻断：抛出 SecurityException
        mv.visitTypeInsn(NEW, "java/lang/SecurityException");
        mv.visitInsn(DUP);
        mv.visitLdcInsn("Request blocked by RASP security policy");
        mv.visitMethodInsn(INVOKESPECIAL, "java/lang/SecurityException",
            "<init>", "(Ljava/lang/String;)V", false);
        mv.visitInsn(ATHROW);

        // 10. 继续执行
        mv.visitLabel(continueLabel);
        mv.visitLabel(skipLabel);
    }

    /**
     * 加载指定索引的局部变量到操作数栈
     */
    private void loadArg(int slotIndex, Type type) {
        int opcode;
        switch (type.getSort()) {
            case Type.BOOLEAN:
            case Type.BYTE:
            case Type.CHAR:
            case Type.SHORT:
            case Type.INT:
                opcode = ILOAD;
                break;
            case Type.LONG:
                opcode = LLOAD;
                break;
            case Type.FLOAT:
                opcode = FLOAD;
                break;
            case Type.DOUBLE:
                opcode = DLOAD;
                break;
            case Type.ARRAY:
            case Type.OBJECT:
                opcode = ALOAD;
                break;
            default:
                opcode = ALOAD;
        }
        mv.visitVarInsn(opcode, slotIndex);
    }

    /**
     * 基本类型装箱为包装类型
     */
    private void boxIfPrimitive(Type type) {
        switch (type.getSort()) {
            case Type.BOOLEAN:
                mv.visitMethodInsn(INVOKESTATIC, "java/lang/Boolean",
                    "valueOf", "(Z)Ljava/lang/Boolean;", false);
                break;
            case Type.BYTE:
                mv.visitMethodInsn(INVOKESTATIC, "java/lang/Byte",
                    "valueOf", "(B)Ljava/lang/Byte;", false);
                break;
            case Type.CHAR:
                mv.visitMethodInsn(INVOKESTATIC, "java/lang/Character",
                    "valueOf", "(C)Ljava/lang/Character;", false);
                break;
            case Type.SHORT:
                mv.visitMethodInsn(INVOKESTATIC, "java/lang/Short",
                    "valueOf", "(S)Ljava/lang/Short;", false);
                break;
            case Type.INT:
                mv.visitMethodInsn(INVOKESTATIC, "java/lang/Integer",
                    "valueOf", "(I)Ljava/lang/Integer;", false);
                break;
            case Type.LONG:
                mv.visitMethodInsn(INVOKESTATIC, "java/lang/Long",
                    "valueOf", "(J)Ljava/lang/Long;", false);
                break;
            case Type.FLOAT:
                mv.visitMethodInsn(INVOKESTATIC, "java/lang/Float",
                    "valueOf", "(F)Ljava/lang/Float;", false);
                break;
            case Type.DOUBLE:
                mv.visitMethodInsn(INVOKESTATIC, "java/lang/Double",
                    "valueOf", "(D)Ljava/lang/Double;", false);
                break;
            // ARRAY, OBJECT: 不需要装箱
        }
    }

    private void pushInt(int value) {
        if (value >= -1 && value <= 5) {
            mv.visitInsn(Opcodes.ICONST_0 + value);
        } else if (value >= Byte.MIN_VALUE && value <= Byte.MAX_VALUE) {
            mv.visitIntInsn(Opcodes.BIPUSH, value);
        } else if (value >= Short.MIN_VALUE && value <= Short.MAX_VALUE) {
            mv.visitIntInsn(Opcodes.SIPUSH, value);
        } else {
            mv.visitLdcInsn(value);
        }
    }
}
