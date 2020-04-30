package com.lee.shiroDemo.config;

import org.apache.shiro.web.filter.authc.FormAuthenticationFilter;
import org.springframework.stereotype.Component;

import javax.servlet.FilterChain;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * Description:
 * User: Lzj
 * Date: 2020-04-30
 * Time: 11:23
 */
@Component
public class LoginFilter extends FormAuthenticationFilter {
    /**
     * 主要用于处理路径的匹配，如果没有设置任何路径拦截，直接通过，
     * 有则遍历匹配后进行处理，处理路径后，会执行 {@link #isFilterChainContinued }方法
     * 其中会返回{@link #onPreHandle(ServletRequest, ServletResponse, Object)}结果
     *
     * @see org.apache.shiro.web.filter.PathMatchingFilter
     *
     * @param request
     * @param response
     * @return
     * @throws Exception
     */
    @Override
    protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
        // System.out.println("preHandle");
        return super.preHandle(request, response);
    }

    /**
     * 在preHandle之后执行
     * @param request
     * @param response
     * @param mappedValue
     * @return
     * @throws Exception
     */
    @Override
    public boolean onPreHandle(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
        // System.out.println("onPreHandle");
        return super.onPreHandle(request, response, mappedValue);
    }

    /**
     * 执行完filterChain后执行的方法 {@link #executeChain(ServletRequest, ServletResponse, FilterChain)}
     * @param request
     * @param response
     * @throws Exception
     */
    @Override
    protected void postHandle(ServletRequest request, ServletResponse response) throws Exception {
        // System.out.println("postHandle");
        super.postHandle(request, response);
    }

    /**
     * 执行完这个filter逻辑后，最后执行的部分，用来处理错误或者清理资源
     * @param request
     * @param response
     * @param exception
     * @throws Exception
     */
    @Override
    public void afterCompletion(ServletRequest request, ServletResponse response, Exception exception) throws Exception {
        System.out.println("afterCompletion");
        super.afterCompletion(request, response, exception);
    }

    /**
     * 父类给出了一个默认实现，跳转回登录页面，但是我们想自己做这个事情，所以可以把他覆盖掉
     * 这个方法通常和{@link #isAccessAllowed(ServletRequest, ServletResponse, Object)}一起
     * 也可以单独实现
     * 这两个方法是在{@link org.apache.shiro.web.filter.AccessControlFilter}中被定义的
     *
     * @param request
     * @param response
     * @return
     * @throws Exception
     */
    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        System.out.println("onAccessDenied");
        return super.onAccessDenied(request, response);
    }
}
