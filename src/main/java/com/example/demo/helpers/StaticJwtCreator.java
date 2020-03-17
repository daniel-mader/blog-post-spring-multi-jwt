package com.example.demo.helpers;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Calendar;
import java.util.Date;

/**
 * Creates a valid statically signed jwt. Usually this is done by some external service or provider.
 */
@Service
public class StaticJwtCreator {

    @Value("${static-jwt.issuer}")
    String issuer;

    @Value("${static-jwt.hmacsecret}")
    String secret;

    public String createToken() {
        try {
            Algorithm algorithm = Algorithm.HMAC256(secret);
            String token = JWT.create()
                    .withIssuer(issuer)
                    .withSubject("staticUser")
                    .withExpiresAt(timeOffset(60 * 60 * 24))
                    .sign(algorithm);
            return token;
        } catch (JWTCreationException exception) {
            // Invalid Signing configuration / Couldn't convert Claims.
            return exception.toString();
        }
    }

    private Date timeOffset(int seconds) {
        Date current = new Date();
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(current);
        calendar.add(Calendar.SECOND, seconds);
        return calendar.getTime();
    }

}
