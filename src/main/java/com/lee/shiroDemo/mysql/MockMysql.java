package com.lee.shiroDemo.mysql;

import com.lee.shiroDemo.entity.User;
import org.springframework.stereotype.Repository;

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

    public void signUp(User userInfo) {
        users.put(userInfo.getUsername(), userInfo);
    }

    public User getUser(String username) {
        return users.get(username);
    }
}
