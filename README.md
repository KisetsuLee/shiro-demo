# shiro 登录框架demo

为啥要用 shiro，emmmmmm，因为公司在用它，我太蔡，都不知道他在做什么神奇的操作，而且也不甘被它欺压，所以苦学一番，对 shiro 的核心概念进行一些总结

## 什么是 shiro

shiro 是一个安全框架，[这里介绍了什么是 shiro](https://www.infoq.com/articles/apache-shiro/)

什么？你说英文难读，其实我也觉得难读，那就摘取官方重点看看吧[1]

Shiro provides the application security API to perform the following aspects (I like to call these the 4 cornerstones of application security):(Shiro 提供了以下应用安全方面的基础 API，当然不止这些)

- Authentication - proving user identity, often called user ‘login’.(验证 —— 提供用户身份验证，就是通常说的登录功能)
- Authorization - access control.(授权 —— 访问特定资源的权限)
- Cryptography - protecting or hiding data from prying eyes.()
- Session Management - per-user time-sensitive state.(会话管理，可以管理每个用户**带状态**的 session)

所以，总的来说就是用来管理我们登录相关的框架了，相当于门神。

## 为什么需要框架

大家都知道客户端(Client)和服务器(Server)通信的时候大多都是通过 http 请求进行通信，而 http 是无状态协议，所以你每一次来访问服务器，服务器都不认识你，这种对面手难牵的感 jio 是不是妨碍了你们和服务器的进一步发展。因为服务器不认识你，所以你只是匿名访问者。

但是因为 Cookie 的存在，服务器就能够知道你是谁，就能将一次次无状态的 http 请求变成带状态的。

一般而言，以 TomCat 为例，每一个用户访问服务器的时候，TomCat 就会在内存生成一个 session 对象，并且在 response 请求中添加了 JSESSIONID 字段的 Cookie。

**session 对象保存在服务端，JSESSIONID 以 cookie 形式保存在客户端，客户端带着这个 cookie，服务端就能根据此 id 值拿到对应的 session 对象**

session 的默认生命周期是此次会话，即客户端关闭浏览器后，cookie 的信息就会被浏览器在本地抹掉，下一次访问时，又是初见。

很久很久以前，有把 login 信息放在 session 的，利用 session 的生命周期(也可以设置 session 在服务器的过期时间)，判断用户是否登录，所以会有这样的代码

```java
// 如果登录了，session中就会有相应的属性(attribute)
HttpSession session = request.getSession(true);

String user = (String) session.getAttribute(SessionNames.USER_KEY);

if (user == null) {
    return 重定向("login");
}
```

这种方式，除了不优雅，而且所有的验证逻辑都需要自己手动写，如果要做权限的控制也是 hin 复杂，要在 session 上保存 hin 多东西，还要为他们一一实现逻辑。

所以框架来了，它们把这些脏活累活全部默默做掉，我们只需要按照自己的需求去定制相关的流程，这也就是 shiro 做的事情。

## shiro 总览

shiro 能够在 JAVASE 环境中和 JAVAEE 环境中使用，你说 JAVASE 的 session 哪来的，放心，shiro 有自己的一套 session 实现，也能和 servlet 容器（Tomcat，jetty 等）进行很好的融合。

shiro 能帮助我们实现认证，授权，加密，会话管理，缓存等功能[2]。

> 以下我引用的，别人说的很好丫，还有 subject 等概念，可以去看看[2]的链接(小声 bb: ……拿了别人的，也可以还一点回去的，哈哈)

#### shiro 总体架构

![shiro蓝图](./images/shiro功能蓝图.png)

Authentication：身份认证/登录，验证用户是不是拥有相应的身份；

Authorization：授权，即权限验证，验证某个已认证的用户是否拥有某个权限；即判断用户是否能做事情，常见的如：验证某个用户是否拥有某个角色。或者细粒度的验证某个用户对某个资源是否具有某个权限；

Session Manager：会话管理，即用户登录后就是一次会话，在没有退出之前，它的所有信息都在会话中；会话可以是普通 JavaSE 环境的，也可以是如 Web 环境的；

Cryptography：加密，保护数据的安全性，如密码加密存储到数据库，而不是明文存储；

Web Support：Web 支持，可以非常容易的集成到 Web 环境；

Caching：缓存，比如用户登录后，其用户信息、拥有的角色/权限不必每次去查，这样可以提高效率；

Concurrency：shiro 支持多线程应用的并发验证，假如在一个线程中开启另一个线程，能把权限自动传播过去；

Testing：提供测试支持；

Run As：允许一个用户假装为另一个用户（如果他们允许）的身份进行访问；

Remember Me：记住我，这个是非常常见的功能，即一次登录后，下次再来的话不用登录了。

以上就是 shiro 的大致架构

#### shiro 执行过程

![shiro执行过程](./images/shiro执行过程.png)

应用的代码经过 shiro 会创建一个与当前线程相绑定的 subject，subject 是一个当前用户，只要与应用交互的任何东西都是 subject

这个 Subject 不干活，但是他负责执行认证和授权的动作（Subject 就只是说要认证，之后就甩手了），之后 Subject 就会被委托给 SecurityManager，安全管理器（SecurityManager）管理着所有的 Subject，是脏活累活的执行者

Realm 是域的意思，它是 shiro 获取安全数据的地方，比如 shiro 要知道你是不是你，需要两份数据对比，一份是外面传进来的，一份就是从 Realm 中获取的，然后 shiro 才能知道你是不是你。

## shiro 实战

**只看不 coding 怎么行呢，这不耍流氓嘛**

**今天不 coding，明天变垃圾**

**反手掏出 IDEA，进行实战吧**

> 现在开发，谁还用 ini 配置文件的？给我出来……夸夸你，很棒棒

2020 年了，实战就使用 springboot，直接开炮

#### 创建项目

有两种方案，一种是 idea 里面创建，第二种是使用[spring initlizr](https://start.spring.io/)，选择 Maven Project，你也可以选择 Gradle Project

我这里就选择了Maven工程

#### 引入相关依赖

然后我们要写关于 Shiro 在 springboot 中的配置，先引入 shiro 的核心及与 spring 集成的包

> pom.xml

```xml
<dependency>
    <groupId>org.apache.shiro</groupId>
    <artifactId>shiro-core</artifactId>
    <version>1.5.1</version>
</dependency>

<dependency>
    <groupId>org.apache.shiro</groupId>
    <artifactId>shiro-spring</artifactId>
    <version>1.5.1</version>
</dependency>
```

#### 创建 web 应用基本框架

我们是 web 项目，自然的需要将基本框架搭好，直接先来一个 controller 和 dao，数据库就用内存数据（Map）代替了

shiro 框架登录逻辑不涉及什么业务层东东，省略掉……

> com.lee.shiroDemo.conroller

```java
@RestController
@RequestMapping("/api")
public class LoginController {
    private LoginDao loginDao;

    @Autowired
    public LoginController(LoginDao loginDao) {
        this.loginDao = loginDao;
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
```

> com.lee.shiroDemo.dao

```java
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
```

再来个非关系型内存数据库

> com.lee.shiroDemo.mysql

```java
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
```

#### 创建 ShiroConfig 配置 bean

从上面的介绍可以得到 SecurityManager 是 shiro 中的小蜜蜂，所以我们先把他给配置了，找到 SecurityManager
这货是一个接口，不过不慌，我们看看他的实现类

![](images/SecurityManager关系图.png)

这么多吗，但是找带 web 关键字的，是不是已经看到候选者了，对，就选择 DefaultWebSecurityManager 这个唯一符合要求的类

使用 java config 配置 bean（喂…… 2020 年了，不会还想着 x…什么的吧……）

> com.lee.shiroDemo.config

```java
@Configuration
public class ShiroConfig {
    @Bean
    public SecurityManager securityManager(SimpleUserRealm realm) {
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        securityManager.setRealm(realm); // 告诉securityManager进行认证的realm
        SecurityUtils.setSecurityManager(securityManager);// 告诉shiro要使用的securityManager
        return securityManager;
    }
}
```

#### 创建 Realm

shiro 是不知道我们要怎样去进行认证的，所以我们还需要一个 Realm，上面说到了，他就是我们进行验证的入口

然后就得到了下面的类，既然是 Realm，当然先继承 Realm 了,然后实现其中的方法

> com.lee.shiroDemo.config

```java
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
```

最后再来个 User 的实体类

> com.lee.shiroDemo.entity

```java
public class User {
    private String username;
    private String password;
    // ... 省略getter setter
}
```

现在就可以用这个例子去创建一个用户进行登录了，这还仅仅只是使用上了shiro的登录管理，接下来给访问设置一点权限的东西

#### 授权

授权，就是给登录用于一个权限，你能做什么，不能做什么，安排的明明白白

授权大致分两种：

- 一种是给用户角色，这种粒度较大，AOE，一动动一片（当然也可以 AOE 大招只大一个）
- 一种是直接给用户授权，这种粒度较小，可以给单个用户开小灶

为了做授权，我们就得为我们 User 类购买一些装备了，添加 roles 和 permissions 字段（老板，两把多兰剑）

```java
public class User {
    private String username;
    private String password;
    private List<Role> roles;
    private List<Permission> permissions;
    // ... 省略getter setter
}

// 再加一个Role类
public class Role {
    private String roleName;
    private List<Permission> permissions;

    // 维护一个Permission，不喜欢的同学可以直接用字符串
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
```

前面我们直接使用的Realm接口，还没有提现出 Authorization 相关的东西

打开 Realm 的继承体系

![](images/realm继承图.png)

这么多…… 先不慌，我们排除看不懂又觉得没用的类，Ldap 是什么？排除！ Text 又是什么？ 排除！ Jdbc 好像有点靠谱，但是访问数据库，我们自己不是也能做吗？

现在看来只能自己实现一个继承 AuthorizingRealm 抽象类的自定义类了

这个类拥有认证和授权的双重作用

修改一下AuthRealm

> com.lee.shiroDemo.config.AuthRealm.java

```java
public class AuthRealm extends AuthorizingRealm {
    // ...
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        System.out.println(1);
        return null;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        // ... 从之前的realm中cv抄过来
    }

    @Override
    public String getName() {
        return "Authentication and authorization user realm.";
    }
}
```

其实只是换了层皮，逻辑都是以前的，记得改掉 ShiroConfig 中的`securityManager.setRealm(realm);`

然后你在`doGetAuthenticationInfo`方法里写了一大堆逻辑，但是好像……

现在的系统，就算不授权，不登录

所有的 controller 还是能畅通无阻的访问

中间好像漏掉了一个东西，filter

#### Filter

shiro 的 filter 是建立在 Servlet 的 filter 基础上的，Shiro代理了Servlet的Filter

执行顺序是先执行完自定义 filter 后，再继续执行 Servlet 中的原始的 filter

关于 filter 更多的细节可以打开(跟他学 filter)[https://www.iteye.com/blog/jinnianshilongnian-2025656][3]

先看 filter 的继承图

![](images/filter.png)

从上面可以看到，在`AccessControlFilter`类下就是认证和授权的 Filter

shiro 存在一些默认的 Filter，在 DefaultFilter 中枚举了默认的 Filter

```java
public enum DefaultFilter {

    anon(AnonymousFilter.class),
    authc(FormAuthenticationFilter.class),
    authcBasic(BasicHttpAuthenticationFilter.class),
    authcBearer(BearerHttpAuthenticationFilter.class),
    logout(LogoutFilter.class),
    noSessionCreation(NoSessionCreationFilter.class),
    perms(PermissionsAuthorizationFilter.class),
    port(PortFilter.class),
    rest(HttpMethodPermissionFilter.class),
    roles(RolesAuthorizationFilter.class),
    ssl(SslFilter.class),
    user(UserFilter.class);
    ...
}
```

如果我们自己实现的 filter，可以去继承他们，或者继承他们的父类，然后注册到`ShiroFilterFactoryBean`中就可以了

在这里我们就不用其默认实现，我们实现自己的 Filter

选择`FormAuthenticationFilter`实现我们自己的 filter，注意看默认 Filter 中它对应的名字`authc`

```java
// LoginFilter
public class LoginFilter extends FormAuthenticationFilter {
    // 我们只覆盖了此方法，原来的默认行为是重定向回登录地址，但是这里我返回一个response
    // 重定向的动作也可以给前端来做
    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        // 如果没有登录我们返回401
        ((HttpServletResponse) response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setCharacterEncoding("utf-8");
        response.getWriter().write("没登录，你在想peach！");
        return false;
    }
}
```

然后把自定义的 filter 交给 shiro 管理

```java
	@Bean
    public ShiroFilterFactoryBean shiroFilter(DefaultWebSecurityManager securityManager) {
        ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
        shiroFilterFactoryBean.setSecurityManager(securityManager);

        // 配置url和对应的角色映射 以下的角色都是shiro内置的
        HashMap<String, String> pattern = new HashMap<>();
        pattern.put("/api/login", "anon");// 匿名访问
        pattern.put("/api/signUp", "anon");
        pattern.put("/api/index", "anon");
        pattern.put("/**", "loginFilter");// 通过认证后访问
        shiroFilterFactoryBean.setFilterChainDefinitionMap(pattern);

        // 注册自定义filter
        LinkedHashMap<String, Filter> filterMap = new LinkedHashMap<>();
        filterMap.put("loginFilter", new LoginFilter());
        shiroFilterFactoryBean.setFilters(filterMap);
        return shiroFilterFactoryBean;
    }
```

测试一下，不登录的时候进行访问，就会返回 401 和~~友好提示~~，而不是重定向了

> 这里有一个天坑，如果你给自定义的 filter 加了 spring 的@Component 注解，它的生命周期就会被 Spring 所管理  
> 这会导致自定义的 filter 在 shiro 体制外，并且在他之前先处理请求  
> 这样请求就还没有进入到 ShiroFilter 的 filter chain，所以拿不到任何登录的信息，就没办法做关于认证，授权的事

#### 授权

在知道怎么让自定义 filter 在 shiro 中生效后，我们就创建自己稀奇古怪的 Filter

![](images/授权filter.png)

可以看到一些默认的实现类，这次我们继承`AccessControlFilter`，完全自定义我们的规则，包括认证和授权，这里就只演示授权了

这之前，回顾一下用户的几个字段，有角色和权限，都是一对多的关系，我们自定义的 filter 是可以对这其中的逻辑进行很灵活的把控（比如拥有角色 admin 的可以访问，拥有角色 guest 并且同时需要拥有 read 权限才可以访问，或者只拥有 super 权限就可以访问……）

> 在我们的例子中，每个角色自带一些权限

```java
// RoleFilter   
// 此类也不要给spring管理，为了取到spring的Bean，自己创建一个SpringContext容器
public class RoleFilter extends AccessControlFilter {
    // todo: 重构一下

    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
        // 因为这个Filter没有被Spring管理，但是又需要获取Spring容器的Bean
        LoginDao loginDao = SpringContext.getBean(LoginDao.class);

        Subject subject = getSubject(request, response);// 获取shiro维护的subject
        String[] rolesArray = (String[]) mappedValue;// 这里得到的就是写在配置文件后面的方括号内容,指定了有权获取资源的角色或权限
        if (rolesArray == null || rolesArray.length == 0) {
            // 没有写就是不要权限访问
            return true;
        }
        // 开始验证工作
        // 1、这里可以选择取得用户身份后，进行验证
        // 2、也可以使用我们之前设置的Realm进行验证
        // shiro提供了一些验证权限和角色的方法，这些方法就进入Realm的doGetAuthorizationInfo获取信息
        // 这里我们采用第一种，因为第二种方式就和默认实现没什么区别，大家可以自己去看看源码
        String principal = (String) subject.getPrincipal();
        if (principal == null || !subject.isAuthenticated()) {
            return false;
        }
        User user = loginDao.getUser(principal);
        if (user == null) {
            return false;
        }

        List<Role> UserRoles = user.getRoles();
        if (UserRoles == null) {
            return false;
        }
        // 拿到用户的roles和roles中自带的permissions
        Set<String> roles = UserRoles.stream().map(Role::getRoleName).collect(Collectors.toSet());
        Set<String> permissions = UserRoles.stream().map(Role::getPermissions).reduce(new ArrayList<>(), (permissionList, current) -> {
            permissionList.addAll(current);
            return permissionList;
        }).stream().map(Role.Permission::getValue).collect(Collectors.toSet());
        // 获取用户自身的权限,合并到permission中去
        List<Role.Permission> userPermissions = user.getPermissions();
        if (userPermissions != null) {
            userPermissions.stream().map(Role.Permission::getValue).forEach(permissions::add);
        }
        // 进行授权认证,这里忽略了配置中的文字，默认只要方括号有字就要鉴权，不管你写了什么（代码人写的，怎么实现都可以）
        return verifyRolesAndPermissions(roles, permissions);
    }

    // 用来验证角色和权限
    private boolean verifyRolesAndPermissions(Set<String> rolesInfos, Set<String> permissionsInfos) {
        // 必须含油admin角色，和写的权限，或者是超人
        return rolesInfos.contains("admin") && permissionsInfos.contains("write") || permissionsInfos.contains("superman");
    }

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        response.setCharacterEncoding(StandardCharsets.UTF_8.toString());
        ((HttpServletResponse) response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.getWriter().write("衣冠不整，恕不招待!");
        return false;
    }
```

然后再改改 ShiroConfig 中的 filter 配置

```java
// ShiroConfig
 @Bean
public ShiroFilterFactoryBean shiroFilter(DefaultWebSecurityManager securityManager) {
    // ...
    // 配置url和对应的角色映射 以下的角色都是shiro内置的
    LinkedHashMap<String, String> pattern = new LinkedHashMap<>();
    pattern.put("/api/login", "anon");// 匿名访问
    pattern.put("/api/signUp", "anon");
    pattern.put("/api/index", "anon");
    // 一个path可以配置多个filter
    pattern.put("/role/admin", "loginFilter, roleFilter[admin]");
    pattern.put("/role/guest", "loginFilter, roleFilter[admin,guest]");
    pattern.put("/**", "loginFilter");// 通过认证后访问
    // ...
}
```

再加一点工具人

```java
// MockMysql
    // ...
    // 创建的角色自带的权限
    List<Role> roles1 = new ArrayList<>();
    roles1.add(new Role("admin", Arrays.asList(Role.Permission.READ, Role.Permission.WRITE)));
    List<Role> roles2 = new ArrayList<>();
    roles2.add(new Role("guest", Collections.singletonList(Role.Permission.READ)));

    User zhangsan = new User("zhangsan", "zhangsan", roles1, Collections.singletonList(Role.Permission.SUPERMAN));
    User lisi = new User("lisi", "lisi", roles2);
    User wangwu = new User("wangwu", "wangwu", null, null);
    User zhaoliu = new User("zhaoliu", "zhaoliu", null, Arrays.asList(Role.Permission.READ, Role.Permission.WRITE));
    User zhouqi = new User("zhouqi", "zhouqi", null, Collections.singletonList(Role.Permission.SUPERMAN));
    //...
```

然后测试一下接口

`/api/admin`需要admin角色和write权限，或者拥有superman权限

前提是都要先登录

测试结果是：只有zhangsan和zhouqi能成功访问

## ~~参考文献~~ 巨人肩膀

[1] https://www.infoq.com/articles/apache-shiro/  
[2] https://www.iteye.com/blog/jinnianshilongnian-2018936  
[3] https://www.iteye.com/blog/jinnianshilongnian-2025656
