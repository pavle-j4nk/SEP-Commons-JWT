# Basic JWT Security
## Description
This project contains basic JWT operations commonly used with Spring Security.  
## Features
* Issue JWT token based on UserDetails
* Authorize every request with valid token
## Usage
To apply provided JWT security simply fetch JwtTokenFilterConfigurer bean and pass it to your HttpSecurity
instance by <i>apply</i> method.  
UserDetailsProvider needs to be provided!  
## Configuration
Properties:
* *security.jwt.token.secret-key* - **mandatory** secret key
* *security.jwt.token.expire-length* - token expiry time. Default is 900000 (15 minutes).
