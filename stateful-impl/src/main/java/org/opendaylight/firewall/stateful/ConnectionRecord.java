/*
 * Copyright (c) 2018 Zhejiang University,Song Shuyu.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
package org.opendaylight.firewall.stateful;

public class ConnectionRecord {
	// immutable fields
		private final String srcIp;
		private final String dstIp;
		private final int srcPort;
		private final int dstPort;
		// counter-- when a FIN packet was found
		private int finCounter = 2 ;
		// initialed when matched with first fin packet
		private String finDirection;
		private int packetCounter = 1 ;
		private long time;
		
		
		public ConnectionRecord(String srcIP, String dstIp, int srcPort, int dstPort) {
			this.srcIp = srcIP ;
			this.dstIp = dstIp ;
			this.srcPort = srcPort ;
			this.dstPort = dstPort ;
			time = System.currentTimeMillis();
		}

		public String getSrcIp() {
			return srcIp;
		}

		public String getDstIp() {
			return dstIp;
		}

		public int getSrcPort() {
			return srcPort;
		}

		public int getDstPort() {
			return dstPort;
		}

		public int getFinCounter() {
			return finCounter;
		}
		public void minusFinCounter() {
			finCounter-- ;
		}
		public String getFinDirection() {
			return finDirection;
		}

		public void setFinDirection(String firstMatchedPktSrcIp) {
			this.finDirection = firstMatchedPktSrcIp;
		}

		public int getPacketCounter() {
			return packetCounter;
		}
		public void addPacketCounter() {
			packetCounter++ ;
			time = System.currentTimeMillis();
		}
		public long getLastTime() {
			return time;
		}

		@Override
		public String toString() {
			
			return ("srcIp = " + srcIp + ", dstIp = " + dstIp + ", srcPort = " +srcPort + ", dstPort = " + dstPort);
		}

	
	
	
	
}
