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
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Description:
 * User: Lzj
 * Date: 2020-04-30
 * Time: 14:06
 */
public class RoleFilter extends AccessControlFilter {

    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
        // 因为这个Filter没有被Spring管理，但是又需要获取Spring容器的Bean
        LoginDao loginDao = SpringContext.getBean(LoginDao.class);

        Subject subject = getSubject(request, response);// 获取shiro维护的subject
        String[] rolesArray = (String[]) mappedValue;// 这里得到的就是写在配置文件后面的方括号内容,指定了有权获取资源的角色或权限
        if (rolesArray == null || rolesArray.length == 0) {
            // 没有写就是不要权限访问
            return true;
        }
        // 开始验证工作
        // 1、这里可以选择取得用户身份后，进行验证
        // 2、也可以使用我们之前设置的Realm进行验证
        // shiro提供了一些验证权限和角色的方法，这些方法就进入Realm的doGetAuthorizationInfo获取信息
        // 这里我们采用第一种，因为第二种方式就和默认实现没什么区别，大家可以自己去看看源码
        String principal = (String) subject.getPrincipal();
        if (principal == null || !subject.isAuthenticated()) {
            return false;
        }
        User user = loginDao.getUser(principal);
        if (user == null) {
            return false;
        }
        // 进行权限的判断，看是不是superman
        List<Role.Permission> userPermissions = user.getPermissions();
        if (userPermissions != null) {
            if (userPermissions.stream().map(Role.Permission::getValue).collect(Collectors.toList()).contains(Role.Permission.SUPERMAN.getValue())) {
                return true;
            }
        }
        List<Role> UserRoles = user.getRoles();
        if (UserRoles == null) {
            return false;
        }
        // 拿到用户的roles和roles中自带的permissions
        Set<String> roles = UserRoles.stream().map(Role::getRoleName).collect(Collectors.toSet());
        Set<String> permissions = UserRoles.stream().map(Role::getPermissions).reduce(new ArrayList<>(), (permissionList, current) -> {
            permissionList.addAll(current);
            return permissionList;
        }).stream().map(Role.Permission::getValue).collect(Collectors.toSet());
        // 用户自身的权限,合并到permission中去
        if (userPermissions != null) {
            userPermissions.stream().map(Role.Permission::getValue).forEach(permissions::add);
        }
        // 进行授权认证,这里忽略了配置中的文字，默认只要方括号有字就要鉴权，不管你写了什么（代码人写的，怎么实现都可以）
        return verifyRolesAndPermissions(roles, permissions);
    }

    private boolean verifyRolesAndPermissions(Set<String> rolesInfos, Set<String> permissionsInfos) {
        // 必须含有admin角色，和写的权限，或者是超人
        return rolesInfos.contains("admin") && permissionsInfos.contains("write") || permissionsInfos.contains("superman");
    }

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        response.setCharacterEncoding(StandardCharsets.UTF_8.toString());
        ((HttpServletResponse) response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.getWriter().write("衣冠不整，恕不招待!");
        return false;
    }
}
