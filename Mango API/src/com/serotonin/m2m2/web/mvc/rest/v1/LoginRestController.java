/**
 * Copyright (C) 2014 Infinite Automation Software. All rights reserved.
 * @author Terry Packer
 */
package com.serotonin.m2m2.web.mvc.rest.v1;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindException;
import org.springframework.validation.DataBinder;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.serotonin.m2m2.Common;
import com.serotonin.m2m2.db.dao.DaoRegistry;
import com.serotonin.m2m2.i18n.TranslatableException;
import com.serotonin.m2m2.i18n.TranslatableMessage;
import com.serotonin.m2m2.module.DefaultPagesDefinition;
import com.serotonin.m2m2.vo.User;
import com.serotonin.m2m2.web.mvc.rest.v1.message.RestProcessResult;
import com.serotonin.m2m2.web.mvc.rest.v1.model.user.UserModel;
import com.wordnik.swagger.annotations.Api;
import com.wordnik.swagger.annotations.ApiOperation;
import com.wordnik.swagger.annotations.ApiParam;

/**
 * Rest Login endpoint
 * 
 * 
 * 
 * 
 * 
 * @author Terry Packer
 * 
 */
@Api(value = "Login", description = "Login")
@RestController
@RequestMapping("/v1/login")
public class LoginRestController extends MangoRestController {

	//private static final Log LOG = LogFactory.getLog(LoginRestController.class);
	public static final String LOGIN_DEFAULT_URI_HEADER = "user-home-uri";
	
	/**
	 * TODO dont use plaintext password, use OAuth2 or HMAC etc
	 * 
     * GET login action
     * @param username
     * @param password
     * @param logout - logout existing user
     * @param request
     * @param response
     * @return
     */
	@ApiOperation(value = "Login", notes = "Login a user")
    @RequestMapping(method = RequestMethod.GET, value = "/{username}",  produces={"application/json"})
    public ResponseEntity<UserModel> login(
            @PathVariable String username,
            @ApiParam(value="User's password")
            @RequestHeader(value="password", required = false, defaultValue = "") String password,
            @ApiParam(value="Logout this session's current user, prior to logging in")
            @RequestHeader(value="logout", required = false, defaultValue = "true") boolean logout,
            HttpServletRequest request, HttpServletResponse response) {

        return performLogin(username, password, request, response, logout, false);
    }
	
	/**
	 * PUT login action
	 * @param username
	 * @param password
	 * @param request
	 * @param response
	 * @return
	 */
	@ApiOperation(value = "Login", notes = "Deprecated, use GET method")
	@Deprecated
	@RequestMapping(method = RequestMethod.PUT, value = "/{username}",  produces={"application/json"})
	public ResponseEntity<UserModel> loginPut(
			@PathVariable String username,
			@RequestParam(value = "password", required = true, defaultValue = "") String password,
			HttpServletRequest request, HttpServletResponse response) {
		return performLogin(username, password, request, response, false, false);
	}

	/**
	 * POST login action
	 * @param username
	 * @param password
	 * @param request
	 * @param response
	 * @return
	 */
	@ApiOperation(value = "Login", notes = "Deprecated, use GET method")
	@Deprecated
	@RequestMapping(method = RequestMethod.POST, value = "/{username}",  produces={"application/json"})
	public ResponseEntity<UserModel> loginPost(
			@PathVariable String username,
			@RequestParam(value = "password", required = true, defaultValue = "") String password,
			HttpServletRequest request, HttpServletResponse response) {
		return performLogin(username, password, request, response, false, false);
	}

	/**
	 * TODO dont use plaintext password, use OAuth2 or HMAC etc
	 * 
     * GET login action to switch user if we are an admin
     * @param username
     * @return
     */
	@ApiOperation(value = "Switch User", notes = "Must be have Administrator priviledges to switch users")
    @RequestMapping(method = RequestMethod.GET, value = "/su/{username}",  produces={"application/json"})
    public ResponseEntity<UserModel> su(
    		@ApiParam(value="Username of user to switch to")
            @PathVariable String username,
            HttpServletRequest request, HttpServletResponse response) {
    	RestProcessResult<UserModel> result = new RestProcessResult<UserModel>(HttpStatus.OK);
    	// check if user is already logged in, if logout == false just return the current user
    	User user = this.checkUser(request, result);
    	
        if (result.isOk()) {
        	if(user.isAdmin()){
	        	User newUser = DaoRegistry.userDao.getUser(username);
	        	
	        	if(newUser == null){
	        		result.addRestMessage(this.getDoesNotExistMessage());
	        		return result.createResponseEntity();
	        	}
	        	String password = newUser.getPassword();
	        	return performLogin(username, password, request, response, true, true);
        	}else{
    			result.addRestMessage(HttpStatus.UNAUTHORIZED, new TranslatableMessage("common.default", "User Not Admin"));
        	}
        }
        
        return result.createResponseEntity();
        
    }
	
	/**
	 * Shared work for the login process.
	 * 
	 * The end result for a logged in user is to have the header user-home-url set 
	 * as well as the homeUrl for the user model.
	 * 
	 * @param username
	 * @param password
	 * @param request
	 * @param response
	 * @return
	 */
	private ResponseEntity<UserModel> performLogin(String username, String password,
			HttpServletRequest request, HttpServletResponse response, boolean logout, boolean passwordEncrypted) {
		
		DataBinder binder = new DataBinder(User.class);
		RestProcessResult<UserModel> result = new RestProcessResult<UserModel>(HttpStatus.OK);
		
		// Hack for now to get a BindException object so we can use the Auth
		// Defs to login.
		BindException errors = new BindException(binder.getBindingResult());

		try{
			User user = Common.loginManager.performLogin(username, password, request, response, null, errors, logout, passwordEncrypted);
			String uri = DefaultPagesDefinition.getDefaultUri(request,
					response, user);
			UserModel model = new UserModel(user);
			if(StringUtils.isEmpty(model.getHomeUrl()))
				model.setHomeUrl(uri);
			result.addHeader(LOGIN_DEFAULT_URI_HEADER, uri);
			//Assign new SessionId to thwart Session Hijacking attempts for pre-login sniffed requests
        	request.changeSessionId();
			return result.createResponseEntity(model);
		}catch(TranslatableException e){
			result.addRestMessage(HttpStatus.NOT_ACCEPTABLE, e.getTranslatableMessage());
			return result.createResponseEntity();
		}
	}
	
}
