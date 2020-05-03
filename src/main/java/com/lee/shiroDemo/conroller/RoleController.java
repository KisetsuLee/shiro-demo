package com.lee.shiroDemo.conroller;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Description:
 * User: Lzj
 * Date: 2020-04-29
 * Time: 17:10
 */
@RestController
@RequestMapping("/role")
public class RoleController {
    @RequestMapping("admin")
    public String admin() {
        return "拥有角色admin";
    }

    @RequestMapping("user")
    public String user() {
        return "拥有角色user";
    }

    @RequestMapping("guest")
    public String guest() {
        return "拥有角色guest";
    }
}
