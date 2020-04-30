package com.lee.shiroDemo.entity;

import java.util.List;

/**
 * Description:
 * User: Lzj
 * Date: 2020-04-29
 * Time: 15:52
 */
public class Role {
    private String roleName;
    private List<Permission> permissions;

    public Role(String roleName, List<Permission> permissions) {
        this.roleName = roleName;
        this.permissions = permissions;
    }

    public String getRoleName() {
        return roleName;
    }

    public void setRoleName(String roleName) {
        this.roleName = roleName;
    }

    public List<Permission> getPermissions() {
        return permissions;
    }

    public void setPermissions(List<Permission> permissions) {
        this.permissions = permissions;
    }

    public enum Permission {
        READ("read"), WRITE("write");
        private String value;

        Permission(String value) {
            this.value = value;
        }

        public String getValue() {
            return value;
        }
    }
}
