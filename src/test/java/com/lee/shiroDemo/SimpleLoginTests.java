package com.lee.shiroDemo;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = ShiroDemoApplication.class)
class SimpleLoginTests {

    @BeforeAll
    void signUp() {

    }

    @Test
    void login() {
    }

}
