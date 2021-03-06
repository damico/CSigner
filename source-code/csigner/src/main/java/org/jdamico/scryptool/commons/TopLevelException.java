/********************************************************************************/
/* 																				*/
/* Copyright [2016]	Robson de Melo Silva,										*/
/* 					Vitoria Akemi Kanegae,										*/
/* 					Jose Ricardo de Oliveira Damico								*/
/* 																				*/
/* Licensed under the Apache License, Version 2.0 (the "License");				*/
/* you may not use this file except in compliance with the License.				*/
/* You may obtain a copy of the License at										*/
/* 																				*/
/*     http://www.apache.org/licenses/LICENSE-2.0								*/
/* 																				*/
/* Unless required by applicable law or agreed to in writing, software			*/
/* distributed under the License is distributed on an "AS IS" BASIS,			*/
/* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.		*/
/* See the License for the specific language governing permissions and			*/
/* limitations under the License.												*/
/*																				*/
/********************************************************************************/

package org.jdamico.scryptool.commons;

import org.jdamico.csigner.Runtime;
import org.jdamico.scryptool.entities.AppProperties;

public class TopLevelException  extends Exception {

	private static final long serialVersionUID = -5433986573983353912L;
	
	private StackTraceElement[] stackTraceElements;
	
	private String message;
	
	public TopLevelException(AppProperties appProperties, String message){
		super(message);
		this.message = message;
		Utils.getInstance().handleVerboseLog(appProperties, 'e', message);
	}
	
	
	public TopLevelException(String errMsg){
		super(errMsg);
		Utils.getInstance().handleVerboseLog(Runtime.appProperties, 'e', errMsg);
	}
	
	public TopLevelException(Exception e){
		super(e);
		Utils.getInstance().handleVerboseLog(Runtime.appProperties, 'e', getStackTraceElements(e));
	}
	
	public TopLevelException(AppProperties appProperties, Exception e){
		super(e);
		Utils.getInstance().handleVerboseLog(appProperties, 'e', getStackTraceElements(e));
	}
	
	public TopLevelException(String errorMessage, Throwable ex) {
		super(errorMessage, ex);
		Utils.getInstance().handleVerboseLog(null, 'e', errorMessage);
	}
	
	
	private String getStackTraceElements(Exception e) {
		this.stackTraceElements = e.getStackTrace();
		StringBuffer sb = new StringBuffer();
		
		if(stackTraceElements == null){
			sb.append(message+" ");
		}else{
			sb.append(message+" ");
			for(int i = 0; i < stackTraceElements.length; i++){
				sb.append(stackTraceElements[i].getFileName()+" ("+stackTraceElements[i].getLineNumber()+")\n");
			}
		}
		
		
		return sb.toString();
	}

	public TopLevelException(){
		super();
		stackTraceElements = getStackTrace();
		Utils.getInstance().handleVerboseLog(null, 'e', getStackTraceElements());
	}
	

	


	


	public String getStackTraceElements(){
		StringBuffer sb = new StringBuffer();
		
		if(stackTraceElements == null){
			sb.append(message);
		}else{
			sb.append(message);
			for(int i = 0; i < stackTraceElements.length; i++){
				sb.append(stackTraceElements[i].getFileName()+"("+stackTraceElements[i].getLineNumber()+")\n");
			}
		}
		
		
		return sb.toString();
	}
	

}