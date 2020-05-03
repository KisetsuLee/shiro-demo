package com.lee.shiroDemo.config;

import com.lee.shiroDemo.dao.LoginDao;
import com.lee.shiroDemo.entity.User;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.springframework.stereotype.Component;

import java.util.Objects;

/**
 * Description:
 * User: Lzj
 * Date: 2020-04-29
 * Time: 17:01
 */
@Component
public class AuthRealm extends AuthorizingRealm {
    private LoginDao loginDao;

    public AuthRealm(LoginDao loginDao) {
        this.loginDao = loginDao;
    }

    @Override
    public boolean supports(AuthenticationToken token) {
        // 如果是UsernamePasswordToken就让其通过
        return token instanceof UsernamePasswordToken;
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        // SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        // User user = (User) principals.getPrimaryPrincipal();
        //
        // return info;
        return null;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        // 得到外部传入的账户密码
        String username = (String) token.getPrincipal(); // 得到用户名
        String password = new String((char[]) token.getCredentials()); // 得到密码
        // 去获取数据库的用户
        User user = loginDao.getUser(username);
        if (user == null) {
            throw new AuthenticationException("用户不存在");
        }
        if (!Objects.equals(user.getUsername(), username)) {
            throw new UnknownAccountException(); // 用户名错误
        }
        if (!Objects.equals(user.getPassword(), password)) {
            throw new IncorrectCredentialsException(); // 密码错误
        }
        //如果身份认证验证成功，返回一个AuthenticationInfo实现；
        return new SimpleAuthenticationInfo(username, password, getName());
    }

    @Override
    public String getName() {
        return "Authentication and authorization user realm.";
    }
}
