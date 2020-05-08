package com.lee.shiroDemo.config;

import com.lee.shiroDemo.dao.LoginDao;
import com.lee.shiroDemo.entity.Role;
import com.lee.shiroDemo.entity.User;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.AccessControlFilter;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Description:
 * User: Lzj
 * Date: 2020-04-30
 * Time: 14:06
 */
public class RoleFilter extends AccessControlFilter {
    // 因为这个Filter没有被Spring管理，但是又需要获取Spring容器的Bean
    private LoginDao loginDao = SpringContext.getBean(LoginDao.class);

    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
        Subject subject = getSubject(request, response);
        String[] rolesArray = (String[]) mappedValue;// 这里得到的就是写在配置文件后面的方括号内容,指定了有权获取资源的角色或权限
        if (rolesArray == null || rolesArray.length == 0) {
            return true;
        }
        // 开始验证工作
        // 1、这里可以选择取得用户身份后，进行验证
        // 2、也可以使用我们之前设置的Realm进行验证
        // shiro提供了一些验证权限和角色的方法，这些方法就进入Realm的doGetAuthorizationInfo获取信息
        // 这里我们采用第一种，因为第二种方式就和默认实现没什么区别，大家可以自己去看看源码
        String principal = (String) subject.getPrincipal();
        User user = loginDao.getUser(principal);
        // 拿到用户的roles和permissions
        List<String> roles = user.getRoles().stream().map(Role::getRoleName).collect(Collectors.toList());
        List<String> permissions = user.getRoles().stream().map(Role::getPermissions).reduce(new ArrayList<>(), (permissionList, current) -> {
            permissionList.addAll(current);
            return permissionList;
        }).stream().map(Role.Permission::getValue).collect(Collectors.toList());

        return false;
    }

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        response.setCharacterEncoding(StandardCharsets.UTF_8.toString());
        ((HttpServletResponse) response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.getWriter().write("你是什么东西？");
        return false;
    }
}
