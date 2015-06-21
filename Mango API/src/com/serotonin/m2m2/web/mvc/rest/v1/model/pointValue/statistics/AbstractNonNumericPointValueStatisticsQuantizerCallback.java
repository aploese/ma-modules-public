/**
 * Copyright (C) 2014 Infinite Automation Software. All rights reserved.
 * @author Terry Packer
 */
package com.serotonin.m2m2.web.mvc.rest.v1.model.pointValue.statistics;

import java.io.IOException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.serotonin.ShouldNeverHappenException;
import com.serotonin.m2m2.view.quantize2.StatisticsGeneratorQuantizerCallback;
import com.serotonin.m2m2.view.stats.ValueChangeCounter;
import com.serotonin.m2m2.web.mvc.rest.v1.model.pointValue.PointValueTimeWriter;
import com.serotonin.m2m2.web.mvc.rest.v1.model.time.RollupEnum;

/**
 * @author Terry Packer
 *
 */
public abstract class AbstractNonNumericPointValueStatisticsQuantizerCallback implements StatisticsGeneratorQuantizerCallback<ValueChangeCounter>{

	private final Log LOG = LogFactory.getLog(AbstractNonNumericPointValueStatisticsQuantizerCallback.class);
	private RollupEnum rollup;
	private PointValueTimeWriter writer;
	

	/**
	 * 
	 * @param writer
	 * @param rollup
	 */
	public AbstractNonNumericPointValueStatisticsQuantizerCallback(PointValueTimeWriter writer, RollupEnum rollup) {
		this.writer= writer;
		this.rollup = rollup;
	}

	/* (non-Javadoc)
	 * @see com.serotonin.m2m2.view.quantize2.StatisticsGeneratorQuantizerCallback#quantizedStatistics(com.serotonin.m2m2.view.stats.StatisticsGenerator, boolean)
	 */
	@Override
    public void quantizedStatistics(ValueChangeCounter statisticsGenerator, boolean done) {
		try{
	        if (statisticsGenerator.getCount() > 0 || !done) {
	            switch(rollup){
	            case FIRST:
	            	this.writer.writeNonNull(statisticsGenerator.getFirstValue(), statisticsGenerator.getPeriodStartTime());
	            break;
	            case LAST:
	            	this.writer.writeNonNull(statisticsGenerator.getLastValue(), statisticsGenerator.getPeriodStartTime());
	            break;
	            case COUNT:
	            	this.writer.writePointValueTime(statisticsGenerator.getCount(), statisticsGenerator.getPeriodStartTime(), null);
	            break;
	            default:
	            	throw new ShouldNeverHappenException("Unsupported Non-numerical Rollup type: " + rollup);
	       
	            }
	        }
		}catch(IOException e){
			LOG.error(e.getMessage(), e);
		}
    }


}