# Practical guide on supporting multiple authentication mechanisms in your Spring Boot application

## Teaser
250 chars

## Introduction
In some of your services you might want to allow your users to use different ways to authenticate.
This guide is for you if you have one of the following problems:
- You might want to allow users to authenticate with OAuth/OpenId Connect and you also want to allow some "technical user" (such as another service) to access your data. That technical user might not get JWTs signed by your central Identity Provider, but who uses some other form of authentication.
- You might also want to migrate from some sort of custom authentication mechanism to the more established and standardized OAuth/OpenID Connect, but you don't want to make the switch in one large big bang and risk locking out some users that haven't yet registered with the Identity Provider and still use the old way.

In both of these cases, you need to support different JWTs in your application.

#### Limitations
We're going to use Java 11 with the popular Spring Framework (Spring Boot 2.2.2).
As OAuth/OpenId Connect is the current gold standard for authentication, we're also going to focus on that protocol.

The goal of this blog post is to guide you in how to configure your Spring Boot Application to support a production-ready state-of-the-art authentication mechanism. I won't explain JWTs, OAuth or OpenID Connect (OIDC) in detail here, but focus on the actual implementation. Some basic understanding of the Spring Framework can help following this guide.

#### Spring standard OpenID Connect
If you only need to support OpenID Connect from a single authorization server, you don't need this guide. Spring makes it easy as pie:
In your `application.yml` you simply specify the issuer of your JWTs:
```yml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: https://idp.example.com/issuer
```
That's it. Spring Boot will use the provided url (Authorization server) to validate the JWTs of incoming requests.

#### Basics
Spring Security reads the `Authorization` header of an incoming HTTP request to determine if a user has valid authentication. The value can either be  `Basic`, followed by an encoded *username:password* value.
If you use a modern application, the value is `Bearer` in most cases. This indicates that the user is in possession of some sort of access token. Those tokens are usually in the JWT (JSON Web Token) format.
Spring passes the incoming request through a so called "Filter Chain" which acts just like a water purification filter system (sand, gravel, charcoal, etc.).
If any of the filters rejects the request for any reason, the chain is broken and the HTTP request is rejected in its entirety. We are going to focus on the `BearerTokenAuthenticationFilter` in this blog post.

#### The problem
Our filter chain is rightfully very strict about rejecting tokens (for example expired ones or incorrectly signed ones), so we might face the problem that our application does not know if a JWT is invalid or just comes from another provider (which we also want to support).
So, how do we tell our application to accept multiple JWTs from different providers while still rejecting invalid ones?

#### The solution
We have two options:
1. We introduce new endpoints and create a new *Spring Security Filter Chain* for each mechanism we want to support. This could look like so:
|| endpoint | To Dos |
|:--:|--|--|
| existing | /products/user?id=ad3f5-92feff-1a22ed3 | everything stays the same, you don't have to touch any existing code
| new | /oauth/products/user?id=ad3f5-92feff-1a22ed3 | gets its own  FilterChain
| new | /myauth/products/user?id=ad3f5-92feff-1a22ed3 | gets its own FilterChain

In this "breadth" approach you would not interfere with your existing auth mechanism, but do you really want to manage double the endpoints?
That is why we should choose the following option:

2. We can also enhance the logic of the current filters ("depth" approach) by adding different `AuthenticationProvider`s to the `BearerTokenAuthenticationFilter`. These providers can create Authentication objects for Spring's `SecurityContext`.

#### Implementation
In the scope of this blog post, we're going to support 3 different ways to authenticate:
1. Basic auth
2. OAuth access tokens signed by a standard OAuth Authorization server (using a dynamic set of public keys that can be fetched from the server)
3. "custom" JWTs signed with some static secret that is shared "out-of-band" with the other party

As Spring has a default AuthenticationProvider built in for the standard OAuth protocol flow, we only need to implement a provider for our own statically signed JWTs. These JWTs should not have the header field **kid** - which would an existing Key ID in a dynamic JSON Web Key Set (JWKS). Such dynamic key sets that change over time are used in OpenID Connect.
We check for the presence of this header field before trying to decode the JWT.

```java
public class StaticJwtAuthenticationProvider implements AuthenticationProvider {

  public JwtDecoder jwtDecoder() {
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
      ...
    }
    if (kid == null) {
      logger.info("JWT header does not contain a JWK Set Key ID. Must be a static token.");
      logger.info("Trying to authenticate ...");
      jwtDecoder().decode(
        ...
      )
    } else {
      return null;
    }
  }
}
```

In order for a Provider to successfully provide authentication to our app, we need to convert the incoming JWT to an Authentication object (such as an `AbstractAuthenticationToken`) .

```java
public class StaticJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

  private final MyUserDetailsService userDetailsService;

  @Override
  public AbstractAuthenticationToken convert(Jwt jwt) {
    String username = jwt.getClaimAsString("sub");
    UserDetails userDetails = userDetailsService.loadUserByUsername(username);
    Collection<GrantedAuthority> authorities = extractAuthorities(jwt);
    // ...
    return new UsernamePasswordAuthenticationToken(userDetails.getUsername(), "n/a", authorities);
  }

}
```

We also need to create a converter for our OAuth tokens.

```java
public class OAuthJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

  private final MyUserDetailsService userDetailsService;

  @Override
  public AbstractAuthenticationToken convert(Jwt jwt) {
    String username = jwt.getClaimAsString("email");
    UserDetails userDetails = userDetailsService.loadUserByUsername(username);
    // ...
    return new UsernamePasswordAuthenticationToken(userDetails.getUsername(), "n/a", authorities);
  }
}
```

> It might make sense to make authentication converters more generic and create some sort of `public abstract class JwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken>` and let other converters extend that converter.

Finally, we need to wire it all together in our `WebSecurityConfiguration`.

```java
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
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

> **IMPORTANT: As this code is crucial for the security of your application, you should always run automated tests! Consider testing successful authentication, but also test that invalid tokens are correctly rejected.**

You can find all of the code in the example above on GitHub: https://github.com/daniel-mader

With the [release of Spring Security 5.2.0](https://docs.spring.io/spring-security/site/docs/5.2.0.RELEASE/reference/htmlsingle/#new), multi-tenancy support was introduced which drastically eases setting up multiple token issuers.
You can read about it in the [official docs](https://docs.spring.io/spring-security/site/docs/current/reference/html5/#oauth2resourceserver-multitenancy).
Implementing multi-tenancy support might be subject of a follow-up blog post.
