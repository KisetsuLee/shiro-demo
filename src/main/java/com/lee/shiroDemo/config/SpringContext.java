package com.lee.shiroDemo.config;

import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.stereotype.Component;

/**
 * Description:
 * User: Lzj
 * Date: 2020-05-08
 * Time: 11:43
 */
@Component
public class SpringContext implements ApplicationContextAware {

    private static ApplicationContext context;

    public static <T extends Object> T getBean(Class<T> beanClass) {
        return context.getBean(beanClass);
    }

    @Override
    public void setApplicationContext(ApplicationContext context) throws BeansException {
        SpringContext.context = context;
    }
}
