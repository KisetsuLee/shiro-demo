package com.lee.shiroDemo.conroller;

import com.lee.shiroDemo.dao.LoginDao;
import com.lee.shiroDemo.entity.User;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;

/**
 * Description:
 * User: Lzj
 * Date: 2020-04-28
 * Time: 10:24
 */
@RestController
@RequestMapping("/api")
public class LoginController {
    private LoginDao loginDao;

    @Autowired
    public LoginController(LoginDao loginDao) {
        this.loginDao = loginDao;
    }

    @GetMapping("index")
    public String index(){
        return "大哥大嫂过年好……我是index";
    }

    @PostMapping("signUp")
    public String signUp(@RequestBody User user, HttpServletResponse response) {
        if (user.getUsername() == null || user.getPassword() == null) {
            response.setStatus(HttpStatus.BAD_REQUEST.value());
            return "注册失败";
        }
        loginDao.signUp(user);
        return "注册成功";
    }

    @PostMapping("login")
    public String login(@RequestBody User user) {
        // 拼装一个token，也就是realm中需要使用到的AuthenticationInfo
        UsernamePasswordToken token = new UsernamePasswordToken();
        token.setUsername(user.getUsername());
        token.setPassword(user.getPassword().toCharArray());

        try {
            SecurityUtils.getSubject().login(token);
        } catch (AuthenticationException e) {
            e.printStackTrace();
            // 这里还有很多子类，可以看看官网
            return "登录失败";
        }
        return "登录成功";
    }
}
