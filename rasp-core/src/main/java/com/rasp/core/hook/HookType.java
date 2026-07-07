package com.rasp.core.hook;

/**
 * Hook 类型
 */
public enum HookType {
    /** 在方法执行前 Hook（最常用） */
    BEFORE,

    /** 在方法执行后 Hook（获取返回值） */
    AFTER,

    /** 方法前后都 Hook */
    AROUND
}
