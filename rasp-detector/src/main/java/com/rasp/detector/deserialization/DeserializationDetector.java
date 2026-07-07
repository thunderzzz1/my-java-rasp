package com.rasp.detector.deserialization;

import com.rasp.commons.AttackType;
import com.rasp.commons.Severity;
import com.rasp.core.context.HookEvent;
import com.rasp.core.context.RaspContext;
import com.rasp.core.detector.DetectResult;
import com.rasp.detector.AbstractDetector;

import java.util.*;

/**
 * 反序列化攻击检测器
 * 
 * Hook ObjectInputStream.resolveClass() 方法，
 * 当反序列化尝试加载已知 Gadget 类时触发阻断。
 * 
 * 黑名单覆盖主流反序列化利用链的关键类。
 */
public class DeserializationDetector extends AbstractDetector {

    /**
     * 已知反序列化 Gadget 类黑名单
     * 参考 ysoserial、marshalsec 等工具中的利用链
     */
    private static final Set<String> GADGET_BLACKLIST = new HashSet<>(Arrays.asList(
        // === JDK 内置 ===
        "java.lang.Runtime",
        "java.lang.ProcessBuilder",
        "javax.management.BadAttributeValueExpException",

        // === Commons Collections ===
        "org.apache.commons.collections.Transformer",
        "org.apache.commons.collections.functors.InvokerTransformer",
        "org.apache.commons.collections.functors.ChainedTransformer",
        "org.apache.commons.collections.functors.ConstantTransformer",
        "org.apache.commons.collections.functors.InstantiateTransformer",
        "org.apache.commons.collections.keyvalue.TiedMapEntry",
        "org.apache.commons.collections.map.LazyMap",
        "org.apache.commons.collections4.functors.InvokerTransformer",
        "org.apache.commons.collections4.functors.ChainedTransformer",
        "org.apache.commons.collections4.functors.ConstantTransformer",
        "org.apache.commons.collections4.functors.InstantiateTransformer",

        // === Commons BeanUtils ===
        "org.apache.commons.beanutils.BeanComparator",

        // === Spring ===
        "org.springframework.beans.factory.ObjectFactory",
        "org.springframework.aop.framework.Advised",
        "org.springframework.transaction.jta.JtaTransactionManager",

        // === Fastjson ===
        "com.sun.rowset.JdbcRowSetImpl",
        "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
        "com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter",
        "org.apache.xalan.xsltc.trax.TemplatesImpl",
        "org.apache.xalan.xsltc.trax.TrAXFilter",

        // === C3P0 ===
        "com.mchange.v2.c3p0.WrapperConnectionPoolDataSource",
        "com.mchange.v2.c3p0.impl.PoolBackedDataSourceBase",

        // === JNDI ===
        "com.sun.jndi.rmi.registry.RegistryContext",
        "com.sun.jndi.ldap.LdapCtx",

        // === BeanShell ===
        "bsh.Interpreter",
        "bsh.XThis",

        // === CGLIB ===
        "net.sf.cglib.proxy.Enhancer",
        "net.sf.cglib.proxy.Factory",

        // === Javassist ===
        "javassist.util.proxy.ProxyFactory",
        "javassist.util.proxy.MethodHandler",

        // === Groovy ===
        "org.codehaus.groovy.runtime.MethodClosure",
        "org.codehaus.groovy.runtime.ConvertedClosure",

        // === Hibernate ===
        "org.hibernate.tuple.component.AbstractComponentTuplizer",
        "org.hibernate.property.BasicPropertyAccessor",

        // === Wicket ===
        "org.apache.wicket.util.upload.DiskFileItem",

        // === Rome ===
        "com.sun.syndication.feed.impl.ObjectBean",

        // === URLDNS ===
        "java.net.URL",
        "java.util.HashMap",

        // === Hessian ===
        "com.caucho.hessian.io.MapDeserializer",
        "com.caucho.hessian.io.BeanDeserializer"
    ));

    /** 类名模式 - 动态代理相关 */
    private static final String DYNAMIC_PROXY_PREFIX = "$Proxy";
    private static final String CGLIB_PROXY_PREFIX = "$$EnhancerBy";
    private static final String JAVASSIST_PROXY_PREFIX = "_$$_jvst";

    public DeserializationDetector() {
        super(AttackType.DESERIALIZATION, "deserialization-detector");
    }

    @Override
    protected DetectResult doDetect(HookEvent event, RaspContext context) {
        // resolveClass() 的参数是反序列化目标类的全限定名
        Object argObj = event.getArgument(0);
        if (!(argObj instanceof String)) {
            // 也可能传入的是 java.io.ObjectStreamClass
            argObj = event.getArgument(0);
            if (argObj == null) return DetectResult.PASS;
            // 尝试通过反射获取类名（ObjectStreamClass.getName()）
            try {
                argObj = argObj.getClass().getMethod("getName").invoke(argObj);
            } catch (Exception e) {
                return DetectResult.PASS;
            }
        }

        String className = argObj.toString();
        if (className == null || className.isEmpty()) {
            return DetectResult.PASS;
        }

        // 检查黑名单
        if (GADGET_BLACKLIST.contains(className)) {
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("dangerous_class", className);

            return DetectResult.block(AttackType.DESERIALIZATION, Severity.HIGH,
                "Deserialization attack blocked: dangerous class '" + className + "' detected",
                evidence);
        }

        // 检查动态生成的代理类（防止 JNDI 注入等利用链）
        if (className.contains(CGLIB_PROXY_PREFIX)
                || className.contains(JAVASSIST_PROXY_PREFIX)) {
            // 需要结合调用栈判断是否从不可信来源触发
            if (context != null) {
                return DetectResult.block(AttackType.DESERIALIZATION, Severity.HIGH,
                    "Deserialization: suspicious proxy class from HTTP request: " + className,
                    Collections.singletonMap("suspicious_class", className));
            }
        }

        return DetectResult.PASS;
    }
}
