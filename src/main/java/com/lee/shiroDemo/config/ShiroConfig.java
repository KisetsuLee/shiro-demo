package com.lee.shiroDemo.config;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Description:
 * User: Lzj
 * Date: 2020-04-28
 * Time: 10:36
 */
@Configuration
public class ShiroConfig {
    @Bean
    public SecurityManager securityManager(SimpleUserRealm realm) {
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        securityManager.setRealm(realm); // 告诉securityManager进行认证的realm
        SecurityUtils.setSecurityManager(securityManager);// 告诉shiro要使用的securityManager
        return securityManager;
    }
}
