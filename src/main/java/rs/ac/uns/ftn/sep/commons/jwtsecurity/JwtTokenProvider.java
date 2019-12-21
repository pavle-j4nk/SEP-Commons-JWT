package rs.ac.uns.ftn.sep.commons.jwtsecurity;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class JwtTokenProvider {
    private static final String AUTHORIZATION = "Authorization";
    private static final String BEARER = "Bearer ";
    private static final String AUTHORITIES_CLAIMS = "aut";

    private final SignatureAlgorithm algorithm = SignatureAlgorithm.RS256;

    private final JwtProperties jwtProperties;
    private final JwtKeys keys;

    public String createToken(UserDetails userDetails) {
        Claims claims = Jwts.claims().setSubject(userDetails.getUsername());
        List<String> authorities = userDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList());
        claims.put(AUTHORITIES_CLAIMS, authorities);

        Date now = new Date();
        Date validity = new Date(now.getTime() + jwtProperties.getDurationMillis());

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(validity)
                .signWith(algorithm, keys.getPrivateKey())
                .compact();
    }

    public Authentication getAuthentication(String token) {
        String username = getUsername(token);
        List<? extends GrantedAuthority> authorities = getAuthorities(token);

        return new UsernamePasswordAuthenticationToken(username, token, authorities);
    }

    public String getUsername(String token) {
        return Jwts.parser().setSigningKey(keys.getPublicKey()).parseClaimsJws(token).getBody().getSubject();
    }

    /**
     * This method try to retrieve username from token
     * even if token is expired.
     *
     * @param token JWT token
     * @return
     */
    public String getUsernameFromExpired(String token) {
        Claims claims;
        try {
            claims = Jwts.parser().setSigningKey(keys.getPublicKey()).parseClaimsJws(token).getBody();
        } catch (ExpiredJwtException e) {
            claims = e.getClaims();
        }

        return claims.getSubject();
    }

    public List<GrantedAuthority> getAuthorities(String token) {
        Claims claims = Jwts.parser().setSigningKey(keys.getPublicKey()).parseClaimsJws(token).getBody();
        List<?> authorityList = claims.get(AUTHORITIES_CLAIMS, List.class);
        String[] authorityArray = authorityList.stream().map(Object::toString).toArray(String[]::new);
        return AuthorityUtils.createAuthorityList(authorityArray);
    }

    public String resolveToken(HttpServletRequest req) {
        String bearerToken = req.getHeader(AUTHORIZATION);
        if (bearerToken != null && bearerToken.startsWith(BEARER)) {
            return bearerToken.substring(BEARER.length());
        }

        return null;
    }

}
