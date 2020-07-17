# How to support different JWTs in your Spring Boot application

![Java CI with Gradle](https://github.com/daniel-mader/blog-post-spring-multi-jwt/workflows/Java%20CI%20with%20Gradle/badge.svg)

**In some of your services you might want to allow your users to use different ways to authenticate.
This guide is for you if you want to support multiple JWTs signed by different issuers (in most cases authorization servers).
I'll explain how to configure Spring Boot to provide a production-ready solution - of course with code examples.**

Link to blog post: https://www.novatec-gmbh.de/en/blog/how-to-support-different-jwts-in-your-spring-boot-application

Or take a look at the [text file](./blog-post/blog-post.md).

---
### Usage
The application offers no graphical user interface, so you need to make API calls via a Terminal or use
a tool like Postman.

The application can be started up with `./gradlew bootRun` and is served at `http://localhost:8080`.

There are 3 REST endpoints available:
* `/whoami` - validates the provided `Authorization` of the calling user and returns their name
* `/health` - can be accessed without any authentication
* `/token/create` - will return a valid "statically signed" token for user **staticUser** (this is only for demo purposes!
Your application MUST NEVER simply hand out valid tokens)

The following test users are hard-coded into the application:
* **basicUser** with password **p@ssw0rd** (as base64: `YmFzaWNVc2VyOnBAc3N3MHJk`)
* **staticUser** (gets an example JWT at `/token/create`)
* **olivia.oauth@test.local** (signs in via an OAuth authorization server)

In a production environment, you would connect to your User database to check for valid users and their roles.

### Running all tests
You can also run all tests to automatically execute each authentication flow. Inspecting the test code can help
to understand how Spring Security handles user authentication.

* install Docker on your machine (needed for a local Keycloak authorization server)
* run all flows with `./gradlew cleanTest test`
* this can take a while on first run: a full-fledged OAuth authorization server (Keycloak) will be automatically started
to execute the OAuth flows
