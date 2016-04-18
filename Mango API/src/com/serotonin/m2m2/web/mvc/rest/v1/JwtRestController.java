/**
 * Copyright (C) 2016 Infinite Automation Software. All rights reserved.
 * @author Jared Wiltshire
 */
package com.serotonin.m2m2.web.mvc.rest.v1;

import java.util.Date;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.serotonin.m2m2.Common;
import com.serotonin.m2m2.db.dao.UserDao;
import com.serotonin.m2m2.vo.User;
import com.serotonin.m2m2.web.mvc.spring.components.JwtService;
import com.wordnik.swagger.annotations.Api;
import com.wordnik.swagger.annotations.ApiOperation;

/**
 * JSON Web Token REST endpoint
 * 
 * @author Jared Wiltshire
 * 
 */
@Api(value = "JWT", description = "JSON web tokens")
@RestController
@RequestMapping("/v1/jwt")
public class JwtRestController extends MangoRestController {

    @Autowired
    JwtService jwtService;

	@ApiOperation(value = "Create token", notes = "Creates a token for a user")
    @RequestMapping(method = RequestMethod.POST, produces={"application/json"})
    public ResponseEntity<String> createToken(
            @RequestBody CreateTokenModel createTokenModel,
            @AuthenticationPrincipal User user,
            Authentication authentication,
            HttpServletRequest request, HttpServletResponse response) {
	    
	    Date expiry = createTokenModel.getExpiry();
	    if (expiry == null) {
	        expiry = new Date(System.currentTimeMillis() + 7 * 24 * 60 * 60 * 1000);
	    }
	    // TODO enforce min/max limits on expiry
	    
	    
	    String username = createTokenModel.getUsername();
	    String password = createTokenModel.getPassword();
	    
        if (username != null && password != null) {
            User requestedUser = UserDao.instance.getUser(username);
            if (requestedUser == null || !Common.checkPassword(password, requestedUser.getPassword())) {
                return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
            }
            return new ResponseEntity<>(jwtService.generateToken(username, expiry), HttpStatus.CREATED);
	    }
        
        // dont allow creation of more tokens if authenticated via token
        if (authentication == null || authentication.getCredentials() instanceof PreAuthenticatedAuthenticationToken
                || user == null) {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }
        
        // TODO check permisison rather than is admin
        if (user.isAdmin()) {
            User requestedUser = UserDao.instance.getUser(username);
            if (requestedUser == null) {
                return new ResponseEntity<>(HttpStatus.NOT_FOUND);
            }
            return new ResponseEntity<>(jwtService.generateToken(username, expiry), HttpStatus.CREATED);
        }
        
        if (username != user.getUsername()) {
            return new ResponseEntity<>(HttpStatus.FORBIDDEN);
        }
        
        return new ResponseEntity<>(jwtService.generateToken(username, expiry), HttpStatus.CREATED);
    }

    public static class CreateTokenModel {
        @JsonProperty
        private String username;
        
        @JsonProperty
        private String password;
        
        @JsonProperty
        private Date expiry;

        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }

        public Date getExpiry() {
            return expiry;
        }

        public void setExpiry(Date expiry) {
            this.expiry = expiry;
        }
    }
}
