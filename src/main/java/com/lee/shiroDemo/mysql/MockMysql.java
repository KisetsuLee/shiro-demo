package com.lee.shiroDemo.mysql;

import com.lee.shiroDemo.entity.Role;
import com.lee.shiroDemo.entity.User;
import org.springframework.stereotype.Repository;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Description:
 * User: Lzj
 * Date: 2020-04-28
 * Time: 10:28
 */
@Repository
public class MockMysql {
    private ConcurrentMap<String, User> users = new ConcurrentHashMap<>();

    public MockMysql() {
        List<Role> roles1 = new ArrayList<>();
        roles1.add(new Role("admin", Arrays.asList(Role.Permission.READ, Role.Permission.WRITE)));
        List<Role> roles2 = new ArrayList<>();
        roles1.add(new Role("admin", Arrays.asList(Role.Permission.READ)));
        User zhangsan = new User("zhangsan", "zhangsan", roles1);
        User lisi = new User("lisi", "lisi", roles2);
        User wangwu = new User("wangwu", "wangwu", null);
        User zhaoliu = new User("zhaoliu", "zhaoliu", null, Arrays.asList(Role.Permission.READ, Role.Permission.WRITE));
        users.put("zhangsan", zhangsan);
        users.put("lisi", lisi);
        users.put("wangwu", wangwu);
        users.put("zhaoliu", zhaoliu);
    }

    public void signUp(User userInfo) {
        users.put(userInfo.getUsername(), userInfo);
    }

    public User getUser(String username) {
        return users.get(username);
    }
}
