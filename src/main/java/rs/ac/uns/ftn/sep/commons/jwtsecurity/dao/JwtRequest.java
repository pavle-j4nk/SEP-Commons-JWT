package rs.ac.uns.ftn.sep.commons.jwtsecurity.dao;

import lombok.Data;

@Data
public class JwtRequest {
    private String username;
    private String password;
}
