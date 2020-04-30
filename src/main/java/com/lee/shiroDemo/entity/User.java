package com.lee.shiroDemo.entity;

import java.util.List;

/**
 * Description:
 * User: Lzj
 * Date: 2020-04-28
 * Time: 10:26
 */
public class User {
    private String username;
    private String password;
    private List<Role> roles;
    private List<Role.Permission> permissions;

    public User() {
    }

    public User(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public User(String username, String password, List<Role> roles) {
        this.username = username;
        this.password = password;
        this.roles = roles;
    }

    public User(String username, String password, List<Role> roles, List<Role.Permission> permissions) {
        this.username = username;
        this.password = password;
        this.roles = roles;
        this.permissions = permissions;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public List<Role> getRoles() {
        return roles;
    }

    public void setRoles(List<Role> roles) {
        this.roles = roles;
    }

    public List<Role.Permission> getPermissions() {
        return permissions;
    }

    public void setPermissions(List<Role.Permission> permissions) {
        this.permissions = permissions;
    }
}
