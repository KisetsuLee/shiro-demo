package com.lee.shiroDemo.config;

import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.AccessControlFilter;
import org.springframework.stereotype.Component;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.nio.charset.StandardCharsets;

/**
 * Description:
 * User: Lzj
 * Date: 2020-04-30
 * Time: 14:06
 */
public class RoleFilter extends AccessControlFilter {

    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
        Subject subject = getSubject(request, response);
        boolean authenticated = subject.isAuthenticated();
        String name = getName();
        System.out.println(name);
        System.out.println(authenticated);
        return false;
    }

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        response.setCharacterEncoding(StandardCharsets.UTF_8.toString());
        response.getWriter().write("你是什么东西？");
        return false;
    }
}
