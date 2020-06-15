# Supporting different JWTs in your Spring Boot application
Link to blog post: https://www.novatec-gmbh.de/en/blog/supporting-different-jwts-in-your-spring-boot-application

---
**In some of your services you might want to allow your users to use different ways to authenticate.
This guide is for you if you want to support multiple JWTs signed by different issuers (in most cases authorization servers).
I'll explain how to configure Spring to provide a production-ready solution - of course with code examples.**

### Introduction
This guide is for you if you face one of the following challenges:
* You might want to allow users to authenticate with OAuth/OpenID Connect and you also want to allow some "technical user" (such as another service) to access your data. That technical user might not get its JSON Web Token (JWT) signed by your central Identity Provider, but could use some other form of authentication.
* You might also want to migrate from some sort of custom authentication mechanism to the more established and standardized OAuth/OpenID Connect, but you don't want to make the switch in one large "big bang" and risk locking out some users that haven't yet registered with the Identity Provider and still use the old way.

In both cases you need to support different JWTs in your application.

### Limitations
We're going to use **Java 11** with **Spring Boot 2.2**. As **OpenID Connect** is the current gold standard for user authentication, we're also going to focus on that protocol.

The goal of this blog post is to guide you in how to configure your Spring Boot Application to support a production-ready state-of-the-art authentication mechanism. I won't explain JSON Web Tokens (JWT), OAuth or OpenID Connect (OIDC) in detail here, but focus on the actual implementation. Some basic understanding of the Spring Framework can help following this guide.

### Standard Spring
If you only need to support OpenID Connect from a single authorization server, you probably won't need this guide. Spring makes it easy as pie:
In your `application.yml` you simply specify the issuer of your JWTs:
```yml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: https://idp.example.com/issuer
```
That's it. Spring Boot will automatically pull the latest keys - in form of a JSON Web Key Set (**JWKS**) - from the authorization server to validate the signatures of incoming JWTs.

### Basics
Spring Security reads the **Authorization** header of an incoming HTTP request to determine if a user has valid authentication.
The value can either be **"Basic"**, followed by an encoded _`username:password`_ value.
In modern web applications however, transferring the user's credentials on each request is not feasible. You'll see the value **"Bearer"** in most cases. This indicates that the user is in possession of some sort of access token instead of a password. Those tokens are usually in the JWT (JSON Web Token) format.
Spring passes the incoming request through a so called "filter chain" - which acts just like a water purification filter system (layered sand, gravel, charcoal, etc.).
If any of the filters rejects the request for any reason, the chain is broken and the HTTP request is rejected in its entirety. We are going to focus on the `BearerTokenAuthenticationFilter` in this blog post.

### The Challenge
Our filter chain is rightfully very strict about rejecting tokens (for example expired ones or incorrectly signed ones), so we might face the problem that our application does not know if a JWT is truly invalid or if it was just signed by another issuer (which we also want to support).
So, how do we tell our application to accept multiple JWTs from different issuers while still rejecting invalid ones?
We essentially have two options now:

1. We introduce new endpoints and create a new <strong>Spring Security Filter Chain</strong> for each mechanism we want to support:
  * keep the existing endpoint and don't change any code:\
  `/products/user?id=ad3f5-92feff-1a22ed3`
  * add another endpoint and handle every request with a dedicated Filter Chain:\
  `/oauth/products/user?id=ad3f5-92feff-1a22ed3`
  * you would have to do this for each way to authenticate:\
  `/my-auth</b>/products/user?id=ad3f5-92feff-1a22ed3`

  Oh, please don't forget to tell your "OAuth users" to use that new <b>/oauth</b> endpoint ...
  Or maybe you could place some gateway or proxy in between and do some rewrite magic ...
  But we don't want to manage double or even triple the endpoints and neither do we want to have more infrastructure and logic in between the application and the user, right?
  (The only advantage of this "breadth" approach is that you wouldn't need to change any of your existing authentication mechanism code.)
  We should rather choose the following option:

2. We can also enhance the logic of the current filters ("depth" approach) by adding different `AuthenticationProvider`s to the `BearerTokenAuthenticationFilter`. These providers can create `Authentication` objects for Spring's `SecurityContext`.

### Let's Code!
In the scope of this blog post, we're going to support 3 different ways to authenticate:
1. **Basic** authentication
2. OAuth access tokens (in form of JWTs), signed by a **standard OpenID Connect** (OIDC) authorization server
3. "Custom" JWTs signed with some **static secret** that is shared "out-of-band" with the other party

As Spring has a default `AuthenticationProvider` already built in for the standard OIDC protocol flow, we only need to implement a provider for our own statically signed JWTs. These JWTs should not have the header field **"kid"** - which would indicate a Key ID in a dynamic JSON Web Key Set (JWKS). Such dynamic sets of public keys that change over time are used in OpenID Connect.
We check for the presence of this header field before trying to decode the JWT.

```java
public class StaticJwtAuthenticationProvider implements AuthenticationProvider {

  public JwtDecoder jwtDecoder() {
    // initialize a decoder with a secret shared "out-of-band"
    SecretKeySpec key = new SecretKeySpec("sup3r-s3cure_secRet".getBytes(StandardCharsets.UTF_8), "HmacSHA256");
    return NimbusJwtDecoder.withSecretKey(key).build();
  }

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    String kid = null;
    try {
      // "DecodedJWT" and "JWT" are from the "java-jwt" library by Auth0 and used for reading the JWT header
      DecodedJWT jwt = JWT.decode(bearerToken.getToken());
      kid = jwt.getKeyId();
    } catch (JWTDecodeException exception) {
      // ...
    }
    if (kid == null) {
      logger.info("JWT header does not contain a JWK Set Key ID. Must be a statically signed token.");
      logger.info("Trying to authenticate ...");
      Jwt jwt = jwtDecoder().decode(((BearerTokenAuthenticationToken) authentication).getToken());
      // ...
    } else {
      return null;
    }
  }
}
```

In order for a Provider to successfully provide authentication to our app, we need to convert the incoming JWT to an `Authentication` object (such as an `AbstractAuthenticationToken`). We'll therefore implement a custom converter:
```java
public class StaticJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

  private final MyUserDetailsService userDetailsService;

  @Override
  public AbstractAuthenticationToken convert(Jwt jwt) {
    String username = jwt.getClaimAsString("sub"); // in this case the username is in the "sub" claim
    UserDetails userDetails = userDetailsService.loadUserByUsername(username);
    Collection authorities = extractAuthorities(jwt);
    // ...
    return new UsernamePasswordAuthenticationToken(userDetails.getUsername(), "n/a", authorities);
  }
}
```

We also need to create a converter for our standard OpenID Connect access tokens:
```java
public class OAuthJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

  private final MyUserDetailsService userDetailsService;

  @Override
  public AbstractAuthenticationToken convert(Jwt jwt) {
    String username = jwt.getClaimAsString("email"); // in this case we take the "email" claim as the username
    UserDetails userDetails = userDetailsService.loadUserByUsername(username);
    // ...
    return new UsernamePasswordAuthenticationToken(userDetails.getUsername(), "n/a", authorities);
  }
}
```

> **Side note:** It might make sense to make authentication converters more generic and create a `public abstract class JwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken>` and let own converters extend that generic converter.

Finally, we need to wire it all together in our `WebSecurityConfiguration`.
```java
@Configuration
@EnableWebSecurity
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

  private final MyUserDetailsService myUserDetailsService;

  @Override
    protected void configure(HttpSecurity http) throws Exception {
      http
        .authorizeRequests()
        .antMatchers("/health").permitAll()
        .anyRequest().authenticated().and()
        // ...
        .oauth2ResourceServer().jwt()
        .jwtAuthenticationConverter(oAuthJwtAuthenticationConverter());
  }

  @Bean
  OAuthJwtAuthenticationConverter oAuthJwtAuthenticationConverter() {
      return new OAuthJwtAuthenticationConverter(myUserDetailsService);
  }

  @Bean
  StaticJwtAuthenticationProvider staticJwtAuthenticationProvider() {
      return new StaticJwtAuthenticationProvider(new StaticJwtAuthenticationConverter(myUserDetailsService));
  }

  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
      auth.authenticationProvider(staticJwtAuthenticationProvider());
      auth.userDetailsService(myUserDetailsService);
      // add Basic auth here ...
  }
}
```

Phew, that's it! Your application should now be ready to correctly authenticate users that use different kinds of JWTs.
>**IMPORTANT: As this code is crucial for the security of your application, you should always run automated tests! You should test valid authentication, but you also need to assure that invalid or expired tokens are correctly rejected.**

You can find all the code on GitHub: https://github.com/daniel-mader/blog-post-spring-multi-jwt

### Multi-tenancy support
With the [release of Spring Security 5.2.0](https://docs.spring.io/spring-security/site/docs/5.2.0.RELEASE/reference/htmlsingle/#new), multi-tenancy support was introduced which drastically eases setting up multiple token issuers. You can read about it in the [official docs](https://docs.spring.io/spring-security/site/docs/current/reference/html5/#oauth2resourceserver-multitenancy).
Implementing multi-tenancy support might be subject of a follow-up blog post.
