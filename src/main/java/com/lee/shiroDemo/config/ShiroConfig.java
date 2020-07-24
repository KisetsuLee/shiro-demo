package com.lee.shiroDemo.config;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.cache.MemoryConstrainedCacheManager;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.servlet.Filter;
import java.util.LinkedHashMap;

/**
 * Description:
 * User: Lzj
 * Date: 2020-04-28
 * Time: 10:36
 */
@Configuration
public class ShiroConfig {

    @Bean
    public DefaultWebSecurityManager securityManager(AuthRealm realm) {
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        securityManager.setSessionManager(new DefaultWebSessionManager());
        securityManager.setRealm(realm); // 告诉securityManager进行认证的realm
        securityManager.setCacheManager(new MemoryConstrainedCacheManager());
        SecurityUtils.setSecurityManager(securityManager);// 告诉shiro要使用的securityManager
        return securityManager;
    }

    @Bean
    public ShiroFilterFactoryBean shiroFilter(DefaultWebSecurityManager securityManager) {
        ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
        shiroFilterFactoryBean.setSecurityManager(securityManager);

        // 配置url和对应的角色映射 以下的角色都是shiro内置的
        LinkedHashMap<String, String> pattern = new LinkedHashMap<>();
        pattern.put("/api/login", "anon");// 匿名访问
        pattern.put("/api/signUp", "anon");
        pattern.put("/api/index", "anon");
        pattern.put("/role/admin", "loginFilter, roleFilter[admin]");
        pattern.put("/role/guest", "loginFilter, roleFilter[admin,guest]");
        pattern.put("/**", "loginFilter"); // 通过认证后访问
        shiroFilterFactoryBean.setFilterChainDefinitionMap(pattern);

        LinkedHashMap<String, Filter> filterMap = new LinkedHashMap<>();
        filterMap.put("loginFilter", new LoginFilter());
        filterMap.put("roleFilter", new RoleFilter());
        shiroFilterFactoryBean.setFilters(filterMap);
        return shiroFilterFactoryBean;
    }

}
