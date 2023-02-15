/*
 * Copyright (c) 2018 Zhejiang University,Song Shuyu.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

package org.opendaylight.firewall.util;

import java.util.ArrayList;
import java.util.List;

import org.opendaylight.yang.gen.v1.urn.ietf.params.xml.ns.yang.ietf.inet.types.rev130715.Ipv4Address;
import org.opendaylight.yang.gen.v1.urn.opendaylight.action.types.rev131112.action.action.DropActionCaseBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.action.types.rev131112.action.action.drop.action._case.DropActionBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.action.types.rev131112.action.list.Action;
import org.opendaylight.yang.gen.v1.urn.opendaylight.action.types.rev131112.action.list.ActionBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.firewall.rules.db.rev180925.L3Rule;
import org.opendaylight.yang.gen.v1.urn.opendaylight.firewall.rules.db.rev180925.firewall.rule.firewall.icmp.rule.IcmpRule;
import org.opendaylight.yang.gen.v1.urn.opendaylight.firewall.rules.db.rev180925.l3.rule.MatchFields;
import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.service.rev130819.SalFlowService;
import org.opendaylight.yang.gen.v1.urn.opendaylight.packet.service.rev130709.PacketProcessingService;
import org.opendaylight.yang.gen.v1.urn.opendaylight.packet.service.rev130709.TransmitPacketInput;
import org.opendaylight.yang.gen.v1.urn.opendaylight.packet.service.rev130709.TransmitPacketInputBuilder;

public class MatchUtil {
	
	public static boolean matchPacketWithIcmpRule(IcmpRule rule,
			Ipv4Address srcIp, Ipv4Address dstIp, Short type, Short code) {
		boolean srcIpMatch = false , dstIpMatch = false, typeMatch = false, codeMatch = false;
		String ruleSrcIp = null, ruleDstIp = null ;
		Short ruleType = null, ruleCode = null;
		if(java.util.Optional.of(rule)
			.map(IcmpRule::getMatchFields)
			.map(org.opendaylight.yang.gen.v1.urn.opendaylight.firewall.rules.db.rev180925.icmp.tuple.MatchFields::getIcmpv4Type)
			.isPresent())
			ruleType = rule.getMatchFields().getIcmpv4Type();
		if(java.util.Optional.of(rule)
				.map(IcmpRule::getMatchFields)
				.map(org.opendaylight.yang.gen.v1.urn.opendaylight.firewall.rules.db.rev180925.icmp.tuple.MatchFields::getIcmpv4Code)
				.isPresent())
			ruleCode = rule.getMatchFields().getIcmpv4Type();
		if(java.util.Optional.of(rule)
				.map(IcmpRule::getMatchFields)
				.map(org.opendaylight.yang.gen.v1.urn.opendaylight.firewall.rules.db.rev180925.icmp.tuple.MatchFields::getIpSource)
				.isPresent()) {
			ruleSrcIp = rule.getMatchFields().getIpSource().getValue();
		}
		if(java.util.Optional.of(rule)
				.map(IcmpRule::getMatchFields)
				.map(org.opendaylight.yang.gen.v1.urn.opendaylight.firewall.rules.db.rev180925.icmp.tuple.MatchFields::getIpDestination)
				.isPresent()) {
			ruleDstIp = rule.getMatchFields().getIpDestination().getValue();
		}
		
		if(ruleType == null || ruleType.equals(type))
			typeMatch = true;
		if(ruleCode == null || ruleCode.equals(code))
			codeMatch = true;
		if(ruleSrcIp == null ||
				match(ruleSrcIp,srcIp.getValue())) {
			srcIpMatch = true ;
		}
		if(ruleDstIp == null ||
				match(ruleDstIp,dstIp.getValue())) {
			dstIpMatch = true ;
		}
		return typeMatch && codeMatch && srcIpMatch && dstIpMatch ;
		
	}
	
	public static boolean matchPacketWithL3Rule(L3Rule rule, 
			Ipv4Address srcIp, Ipv4Address dstIp, Integer srcPort, Integer dstPort) {
		//these four boolean values record match results of each field in rule;
		boolean srcIpMatch = false , dstIpMatch = false, srcPortMatch = false, dstPortMatch = false;
	//	LOG.info("match with rule {}",rule);
		//wildcard field is regarded as matched with any value;
		// if a field is not wildcard(null) , compare it with corresponding field of packet
		Integer ruleSrcPort = null, ruleDstPort = null;
		String  ruleSrcIp = null, ruleDstIp = null ;
		if(java.util.Optional.of(rule)
			.map(L3Rule::getMatchFields)
			.map(MatchFields::getTcpSourcePort)
			.isPresent()) {
			ruleSrcPort = rule.getMatchFields().getTcpSourcePort().getValue();
		}
		if(java.util.Optional.of(rule)
				.map(L3Rule::getMatchFields)
				.map(MatchFields::getTcpDestinationPort)
				.isPresent()) {
				ruleDstPort = rule.getMatchFields().getTcpDestinationPort().getValue();
		}
		if(java.util.Optional.of(rule)
				.map(L3Rule::getMatchFields)
				.map(MatchFields::getIpSource)
				.isPresent()) {
				ruleSrcIp = rule.getMatchFields().getIpSource().getValue();
		}
		if(java.util.Optional.of(rule)
				.map(L3Rule::getMatchFields)
				.map(MatchFields::getIpDestination)
				.isPresent()) {
				ruleDstIp = rule.getMatchFields().getIpDestination().getValue();
			}
		
		if(ruleSrcPort == null || 
				ruleSrcPort.equals(srcPort)) {
			srcPortMatch = true ;
		}
		if(ruleDstPort == null ||
				ruleDstPort.equals(dstPort)) {
			dstPortMatch = true ;
		}
		if(ruleSrcIp == null ||
				match(ruleSrcIp,srcIp.getValue())) {
			srcIpMatch = true ;
		}
		if(ruleDstIp == null ||
				match(ruleDstIp,dstIp.getValue())) {
			dstIpMatch = true ;
		}
		
		return srcIpMatch && dstIpMatch && srcPortMatch && dstPortMatch ;
		
	}
	
	/*
	 * match ip(src and dest) of tcp packet with rule-ip with prefix;
	 * @return true if the ip of tcp packet belong to the segment network specfied by rule-ip with prefix
	 * 
	 */
	private static boolean match(String ruleIp, String pktIp) {
		String ruleIpNoMask = ruleIp.split("/")[0];
		String mask = ruleIp.split("/")[1];
		int ruleIp1int = to1Int(ruleIpNoMask);
		int pktIp1int = to1Int(pktIp);
		int maskToAndOperator = 0 ;
		//convert the string mask to a 32 bits int ,for example:
		// 24 = 0xfff0; 30 = b11111111111111111111111111111100;
		for(int i=0;i<32;i++) {
			if(i > (32 - Integer.parseInt(mask) - 1)) {
				//1 << i == 2^i ;
				maskToAndOperator += (1 << i);
			}
		}
		return (ruleIp1int & maskToAndOperator ) == (pktIp1int & maskToAndOperator);
		
		
	}
	/*
	 * convert the String ip to a 32 bits int
	 * 1. split ip to 4 parts by the  regular expression "\\."
	 * 2. cast string to int 
	 * 3. join 4 int values by add and left shift operators , so that we can get a 32 bits int value
	 */
	private static int to1Int(String ipNoMask) {
		String[] parsedIP = ipNoMask.split("\\.");
		int[] ip4int = new int[4];
		for(int i=0;i<4;i++) {
			ip4int[i] = Integer.parseInt(parsedIP[i]);
		}
		int i = (ip4int[0] << 24) //
				+ (ip4int[1] << 16) //
				+ (ip4int[2] << 8) //
				+ (ip4int[3]) ;
		return i ;
	}

}
