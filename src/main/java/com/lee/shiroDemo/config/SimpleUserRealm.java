package com.lee.shiroDemo.config;

import com.lee.shiroDemo.dao.LoginDao;
import com.lee.shiroDemo.entity.User;
import org.apache.shiro.authc.*;
import org.apache.shiro.realm.Realm;
import org.springframework.stereotype.Component;

import java.util.Objects;

/**
 * Description:
 * User: Lzj
 * Date: 2020-04-28
 * Time: 11:30
 */
@Component
public class SimpleUserRealm implements Realm {
    private LoginDao loginDao;

    public SimpleUserRealm(LoginDao loginDao) {
        this.loginDao = loginDao;
    }

    /**
     * realm的名字，自己自定义
     *
     * @return
     */
    @Override
    public String getName() {
        return "simple user realm.";
    }

    /**
     * 看传入的token被不被这个realm支持
     *
     * @param token
     * @return
     */
    @Override
    public boolean supports(AuthenticationToken token) {
        // 如果是UsernamePasswordToken就让其通过
        return token instanceof UsernamePasswordToken;
    }

    /**
     * token就是外面出入的信息，在这里可以进行认证
     *
     * @param token
     * @return
     * @throws AuthenticationException
     */
    @Override
    public AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
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
}
