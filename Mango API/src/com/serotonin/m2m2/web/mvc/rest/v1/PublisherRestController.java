/**
 * Copyright (C) 2014 Infinite Automation Software. All rights reserved.
 * @author Terry Packer
 */
package com.serotonin.m2m2.web.mvc.rest.v1;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.UriComponentsBuilder;

import com.serotonin.m2m2.Common;
import com.serotonin.m2m2.db.dao.DaoRegistry;
import com.serotonin.m2m2.db.dao.PublisherDao;
import com.serotonin.m2m2.i18n.ProcessResult;
import com.serotonin.m2m2.vo.User;
import com.serotonin.m2m2.vo.dataSource.DataSourceVO;
import com.serotonin.m2m2.vo.permission.PermissionException;
import com.serotonin.m2m2.vo.permission.Permissions;
import com.serotonin.m2m2.vo.publish.PublisherVO;
import com.serotonin.m2m2.web.mvc.rest.v1.message.RestProcessResult;
import com.serotonin.m2m2.web.mvc.rest.v1.model.AbstractDataSourceModel;
import com.serotonin.m2m2.web.mvc.rest.v1.model.publisher.AbstractPublisherModel;
import com.wordnik.swagger.annotations.Api;
import com.wordnik.swagger.annotations.ApiOperation;

/**
 * @author Terry Packer
 * 
 */
@Api(value="Publishers", description="Publishers")
@RestController
@RequestMapping("/v1/publishers")
public class PublisherRestController extends MangoVoRestController<PublisherVO<?>, AbstractPublisherModel<?, ?>, PublisherDao>{

	public PublisherRestController(){
		super(DaoRegistry.publisherDao);
	}
	private static Log LOG = LogFactory.getLog(PublisherRestController.class);
	
//	@ApiOperation(
//			value = "Query Publishers",
//			notes = "Use RQL formatted query",
//			response=DataPointModel.class,
//			responseContainer="List"
//			)
//	@RequestMapping(method = RequestMethod.GET, produces={"application/json"})
//    public ResponseEntity<QueryDataPageStream<PublisherVO<?>>> queryRQL(
//    		   		   		
//    		HttpServletRequest request) {
//		
//		RestProcessResult<QueryDataPageStream<DataSourceVO<?>>> result = new RestProcessResult<QueryDataPageStream<DataSourceVO<?>>>(HttpStatus.OK);
//    	User user = this.checkUser(request, result);
//    	if(result.isOk()){
//    		try{
//    			ASTNode node = this.parseRQLtoAST(request);
//    			PublisherStreamCallback callback = new PublisherStreamCallback(this, user);
//    			return result.createResponseEntity(getPageStream(node, callback));
//    		}catch(UnsupportedEncodingException | RQLToSQLParseException e){
//    			LOG.error(e.getMessage(), e);
//    			result.addRestMessage(getInternalServerErrorMessage(e.getMessage()));
//				return result.createResponseEntity();
//    		}
//    	}
//    	return result.createResponseEntity();
//	}
	
	@ApiOperation(
			value = "Get all data publishers",
			notes = "Only returns publishers available to logged in user"
			)
    @RequestMapping(method = RequestMethod.GET, produces={"application/json"}, value = "/list")
    @ResponseStatus(HttpStatus.OK)
    public ResponseEntity<List<AbstractPublisherModel<?,?>>> getAll(HttpServletRequest request) {
    	
    	RestProcessResult<List<AbstractPublisherModel<?,?>>> result = new RestProcessResult<List<AbstractPublisherModel<?,?>>>(HttpStatus.OK);
    	
    	User user = this.checkUser(request, result);
    	if(result.isOk()){
	        List<PublisherVO<?>> publishers = DaoRegistry.publisherDao.getAll();
	        List<AbstractPublisherModel<?,?>> models = new ArrayList<AbstractPublisherModel<?,?>>();
	        for(PublisherVO<?> pub : publishers){
	        	try{
	        		//TODO No permissions yet...
	        		//if(Permissions.hasDataSourcePermission(user, ds))
	        			models.add(pub.asModel());
	        	}catch(PermissionException e){
	        		//Munch Munch
	        	}
	        	
	        }
	        return result.createResponseEntity(models);
    	}
    	return result.createResponseEntity();
    }
	
	@ApiOperation(
			value = "Get publisher by xid",
			notes = "Only returns publishers available to logged in user"
			)
	@RequestMapping(method = RequestMethod.GET, value = "/{xid}", produces={"application/json"})
    public ResponseEntity<AbstractPublisherModel<?,?>> getPublisher(HttpServletRequest request, @PathVariable String xid) {
		
		RestProcessResult<AbstractPublisherModel<?,?>> result = new RestProcessResult<AbstractPublisherModel<?,?>>(HttpStatus.OK);
		User user = this.checkUser(request, result);
    	if(result.isOk()){
            PublisherVO<?> vo = DaoRegistry.publisherDao.getByXid(xid);

            if (vo == null) {
                return new ResponseEntity<AbstractPublisherModel<?,?>>(HttpStatus.NOT_FOUND);
            }else{
            	try{
	        		//TODO Permissions
            		//if(Permissions.hasDataSourcePermission(user, vo))
	        			return result.createResponseEntity(vo.asModel());
	        		//else{
	    	    	//	result.addRestMessage(getUnauthorizedMessage());
	            	//	return result.createResponseEntity();
	        		//}
	        	}catch(PermissionException e){
	        		LOG.warn(e.getMessage(), e);
		    		result.addRestMessage(getUnauthorizedMessage());
	        		return result.createResponseEntity();
	        	}
            }
    	}
        return result.createResponseEntity();
    }
	
	
	
	/**
	 * Update a publisher
	 * @param xid
	 * @param model
     * @param builder
	 * @param request
	 * @return
	 */
	@ApiOperation(value = "Update data source")
	@RequestMapping(method = RequestMethod.PUT, value = "/{xid}", produces={"application/json"})
    public ResponseEntity<AbstractPublisherModel<?,?>> updatePublisher(
    		@PathVariable String xid,
    		@RequestBody AbstractPublisherModel<?,?> model, 
    		UriComponentsBuilder builder, 
    		HttpServletRequest request) {

		RestProcessResult<AbstractPublisherModel<?,?>> result = new RestProcessResult<AbstractPublisherModel<?,?>>(HttpStatus.OK);

		User user = this.checkUser(request, result);
        if(result.isOk()){
        	PublisherVO<?> vo = model.getData();
			
	        PublisherVO<?> existing = DaoRegistry.publisherDao.getByXid(xid);
	        if (existing == null) {
	    		result.addRestMessage(getDoesNotExistMessage());
	    		return result.createResponseEntity();
	        }
	        
	        //Check permissions
	    	try{
	    		if(!user.isAdmin()){
	    			result.addRestMessage(getUnauthorizedMessage());
	        		return result.createResponseEntity();
	    		}
	    	}catch(PermissionException e){
	    		LOG.warn(e.getMessage(), e);
	    		result.addRestMessage(getUnauthorizedMessage());
        		return result.createResponseEntity();
        	}
	
	        vo.setId(existing.getId());
	        
	        ProcessResult validation = new ProcessResult();
	        vo.validate(validation);
	        
	        if(!model.validate()){
	        	result.addRestMessage(this.getValidationFailedError());
	        	return result.createResponseEntity(model); 
	        }else{
	            Common.runtimeManager.savePublisher(vo);
	        }
	        
	        //Put a link to the updated data in the header?
	    	URI location = builder.path("/v1/publishers/{xid}").buildAndExpand(xid).toUri();
	    	result.addRestMessage(getResourceUpdatedMessage(location));
	        return result.createResponseEntity(model);
        }
        //Not logged in
        return result.createResponseEntity();
    }
//
//	@ApiOperation(value = "Save data source")
//	@RequestMapping(
//			method = {RequestMethod.POST},
//			produces = {"application/json"}
//	)
//	public ResponseEntity<AbstractDataSourceModel<?>> saveDataSource(@RequestBody AbstractDataSourceModel<?> model, UriComponentsBuilder builder, HttpServletRequest request) {
//		RestProcessResult<AbstractDataSourceModel<?>> result = new RestProcessResult<AbstractDataSourceModel<?>>(HttpStatus.OK);
//		User user = this.checkUser(request, result);
//		if(result.isOk()) {
//			
//			try {
//				if(!Permissions.hasDataSourcePermission(user)) {
//					result.addRestMessage(this.getUnauthorizedMessage());
//					return result.createResponseEntity();
//				}
//			} catch (PermissionException pe) {
//				LOG.warn(pe.getMessage(), pe);
//				result.addRestMessage(this.getUnauthorizedMessage());
//				return result.createResponseEntity();
//			}
//			
//			DataSourceVO<?> vo = model.getData();
//			DataSourceVO<?> existing = (DataSourceVO<?>)DaoRegistry.dataSourceDao.getByXid(model.getXid());
//			if(existing != null) {
//				result.addRestMessage(this.getAlreadyExistsMessage());
//				return result.createResponseEntity();
//			} else {
//				ProcessResult validation = new ProcessResult();
//				vo.validate(validation);
//				if(!model.validate()) {
//					result.addRestMessage(this.getValidationFailedError());
//					return result.createResponseEntity(model);
//				}
//				else {
//					Common.runtimeManager.saveDataSource(vo);
//					DataSourceVO<?> created = (DataSourceVO<?>)DaoRegistry.dataSourceDao.getByXid(model.getXid());
//					URI location = builder.path("/v1/data-sources/{xid}").buildAndExpand(new Object[]{created.asModel().getXid()}).toUri();
//					result.addRestMessage(this.getResourceCreatedMessage(location));
//					return result.createResponseEntity(created.asModel());
//				}
//			}
//		} else {
//			return result.createResponseEntity();
//		}
//	}
//
//
//	@ApiOperation(value = "Delete data source")
//	@RequestMapping(
//			method = {RequestMethod.DELETE},
//			value = {"/{xid}"},
//			produces = {"application/json"}
//	)
//	public ResponseEntity<AbstractDataSourceModel<?>> deleteDataSource(@PathVariable String xid, UriComponentsBuilder builder, HttpServletRequest request) {
//		RestProcessResult<AbstractDataSourceModel<?>> result = new RestProcessResult<AbstractDataSourceModel<?>>(HttpStatus.OK);
//		User user = this.checkUser(request, result);
//		if(result.isOk()) {
//			DataSourceVO<?> existing = (DataSourceVO<?>)DaoRegistry.dataSourceDao.getByXid(xid);
//			if(existing == null) {
//				result.addRestMessage(this.getDoesNotExistMessage());
//				return result.createResponseEntity();
//			} else {
//				try {
//					if(!Permissions.hasDataSourcePermission(user, existing.getId())) {
//						result.addRestMessage(this.getUnauthorizedMessage());
//						return result.createResponseEntity();
//					}
//				} catch (PermissionException pe) {
//					LOG.warn(pe.getMessage(), pe);
//					result.addRestMessage(this.getUnauthorizedMessage());
//					return result.createResponseEntity();
//				}
//
//				Common.runtimeManager.deleteDataSource(existing.getId());
//				return result.createResponseEntity(existing.asModel());
//			}
//		}
//		return result.createResponseEntity();
//	}

	/* (non-Javadoc)
	 * @see com.serotonin.m2m2.web.mvc.rest.v1.MangoVoRestController#createModel(java.lang.Object)
	 */
	@Override
	public AbstractPublisherModel<?,?> createModel(PublisherVO<?> vo) {
		if(vo != null)
			return vo.asModel();
		else
			return null;
	}

}
