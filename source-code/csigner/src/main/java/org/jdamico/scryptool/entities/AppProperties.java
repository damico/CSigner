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

package org.jdamico.scryptool.entities;

public class AppProperties {
	
	
	private String libPath = null;
	private String verbose = null;
	private String log = null;

	public static final String[] KEY_NAMES = new String[]{"libpath", "verbose", "log"};
	
	public AppProperties(String libPath, String verbose, String log) {
		super();
		this.libPath = libPath;
		this.verbose = verbose;
		this.log = log;
	}

	public String getLibPath() {
		return libPath;
	}

	public void setLibPath(String libPath) {
		this.libPath = libPath;
	}

	public String getVerbose() {
		return verbose;
	}

	public void setVerbose(String verbose) {
		this.verbose = verbose;
	}

	public String getLog() {
		return log;
	}

	public void setLog(String log) {
		this.log = log;
	}


}
