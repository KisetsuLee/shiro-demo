package com.lee.shiroDemo.dao;

import com.lee.shiroDemo.entity.User;
import com.lee.shiroDemo.mysql.MockMysql;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

/**
 * Description:
 * User: Lzj
 * Date: 2020-04-28
 * Time: 11:57
 */
@Repository
public class LoginDao {
    private MockMysql database;

    @Autowired
    public LoginDao(MockMysql database) {
        this.database = database;
    }

    public void signUp(User user) {
        database.signUp(user);
    }

    public User getUser(String username) {
        return database.getUser(username);
    }
}
