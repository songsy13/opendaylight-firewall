/*
 * Copyright (c) 2018 Zhejiang University,Song Shuyu.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

package org.opendaylight.firewall.stateless;

import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.opendaylight.controller.md.sal.binding.api.DataBroker;
import org.opendaylight.controller.md.sal.binding.api.ReadWriteTransaction;
import org.opendaylight.controller.md.sal.common.api.data.LogicalDatastoreType;
import org.opendaylight.controller.md.sal.common.api.data.ReadFailedException;
import org.opendaylight.controller.md.sal.common.api.data.TransactionCommitFailedException;
import org.opendaylight.firewall.util.Decision;
import org.opendaylight.firewall.util.MatchUtil;
import org.opendaylight.yang.gen.v1.urn.ietf.params.xml.ns.yang.ietf.inet.types.rev130715.Ipv4Address;
import org.opendaylight.yang.gen.v1.urn.opendaylight.firewall.rev180925.ReactiveFlowConfig;
import org.opendaylight.yang.gen.v1.urn.opendaylight.firewall.rules.db.rev180925.FirewallRule;
import org.opendaylight.yang.gen.v1.urn.opendaylight.firewall.rules.db.rev180925.firewall.rule.FirewallUdpRule;
import org.opendaylight.yang.gen.v1.urn.opendaylight.firewall.rules.db.rev180925.firewall.rule.FirewallUdpRuleBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.firewall.rules.db.rev180925.firewall.rule.firewall.udp.rule.UdpRule;
import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.inventory.rev130819.tables.table.Flow;
import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.service.rev130819.SalFlowService;
import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.types.rev131026.flow.Instructions;
import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.types.rev131026.flow.Match;
import org.opendaylight.yang.gen.v1.urn.opendaylight.inventory.rev130819.NodeConnectorRef;
import org.opendaylight.yang.gen.v1.urn.opendaylight.inventory.rev130819.nodes.Node;
import org.opendaylight.yang.gen.v1.urn.opendaylight.packet.basepacket.rev140528.packet.chain.grp.PacketChain;
import org.opendaylight.yang.gen.v1.urn.opendaylight.packet.basepacket.rev140528.packet.chain.grp.packet.chain.packet.RawPacket;
import org.opendaylight.yang.gen.v1.urn.opendaylight.packet.ethernet.rev140528.ethernet.packet.received.packet.chain.packet.EthernetPacket;
import org.opendaylight.yang.gen.v1.urn.opendaylight.packet.ipv4.rev140528.ipv4.packet.received.packet.chain.packet.Ipv4Packet;
import org.opendaylight.yang.gen.v1.urn.opendaylight.packet.ipv4.udp.rev180925.UdpPacketListener;
import org.opendaylight.yang.gen.v1.urn.opendaylight.packet.ipv4.udp.rev180925.UdpPacketReceived;
import org.opendaylight.yang.gen.v1.urn.opendaylight.packet.ipv4.udp.rev180925.udp.packet.received.packet.chain.packet.UdpPacket;
import org.opendaylight.yang.gen.v1.urn.opendaylight.packet.service.rev130709.PacketProcessingService;
import org.opendaylight.yangtools.yang.binding.InstanceIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Optional;
import com.google.common.base.Preconditions;
import com.google.common.util.concurrent.CheckedFuture;


public class UdpPacketProcessor implements UdpPacketListener {
	
	private static final Logger LOG = LoggerFactory.getLogger(UdpPacketProcessor.class);
	private static final int CPUS = Runtime.getRuntime().availableProcessors();
	private final ExecutorService executor = Executors.newFixedThreadPool(CPUS);
	
	private final DataBroker dataBroker;
	private final PacketProcessingService packetProcessingService;
	private final SalFlowService salFlowService;
	private final ReactiveFlowConfig reactiveFlowConfig;
	private ReactiveFlowWriterPacketOut reactiveFlowWriterPacketOut;
	 
	
	
	public UdpPacketProcessor(DataBroker dataBroker, PacketProcessingService packetProcessingService
			, SalFlowService salFlowService, ReactiveFlowConfig reactiveFlowConfig){
		this.dataBroker = dataBroker;
		this.packetProcessingService = packetProcessingService;
		this.salFlowService = salFlowService;
		this.reactiveFlowConfig = reactiveFlowConfig;
	}
	public void init() {
		LOG.info("UdpListener initialized; Dispatcher a ReactiveFlowWriter to UdpPacketProcessor");
		this.reactiveFlowWriterPacketOut = new ReactiveFlowWriterPacketOut(salFlowService, packetProcessingService,reactiveFlowConfig,dataBroker);
	}
	public void close() {
		LOG.info("UdpListener shut down");
	}
	

	@Override
	public void onUdpPacketReceived(UdpPacketReceived udpPacketReceived) {
		LOG.info("Receive a UDP packet");
		if(udpPacketReceived == null || udpPacketReceived.getPacketChain() == null) {
			return;
		}
		 RawPacket rawPacket = null ;
		 EthernetPacket ethernetPacket = null ;
		 Ipv4Packet ipv4Packet = null ;
		 UdpPacket udpPacket = null ;
		 
		 for(PacketChain packetChain : udpPacketReceived.getPacketChain()) {
				if (packetChain.getPacket() instanceof RawPacket) {
	               rawPacket = (RawPacket) packetChain.getPacket();
	            } else if (packetChain.getPacket() instanceof EthernetPacket) {
	               ethernetPacket = (EthernetPacket) packetChain.getPacket();
	            } else if (packetChain.getPacket() instanceof Ipv4Packet) {
	               ipv4Packet = (Ipv4Packet) packetChain.getPacket();
	            }else if(packetChain.getPacket() instanceof UdpPacket) {
	            	udpPacket = (UdpPacket)packetChain.getPacket();
	            }
		 }
		 
		 if(rawPacket == null || ethernetPacket == null || ipv4Packet == null || udpPacket == null) {
			 return;
		 }
		 executor.submit(new PacketProcessing(udpPacketReceived, rawPacket, ethernetPacket, ipv4Packet, udpPacket));
		 
		 
	}
	
	private class PacketProcessing implements Runnable{
		
		private FirewallUdpRule udpRules;
		private final UdpPacketReceived udpPacketReceived;
		private final RawPacket rawPacket  ;
		private final EthernetPacket ethernetPacket;
		private final Ipv4Packet ipv4Packet ;
		private final UdpPacket udpPacket;
		
		
		public PacketProcessing(UdpPacketReceived udpPacketReceived, RawPacket rawPacket, EthernetPacket ethernetPacket,
				Ipv4Packet ipv4Packet, UdpPacket udpPacket) {
			// TODO Auto-generated constructor stub
			this.udpPacketReceived = udpPacketReceived;
			this.rawPacket = rawPacket;
			this.ethernetPacket = ethernetPacket;
			this.ipv4Packet = ipv4Packet;
			this.udpPacket = udpPacket;
		}
		

		@Override
		public void run() {
			//LOG.info("Receive a UDP packet");
			Decision result = matchPacketWithRules(ipv4Packet.getSourceIpv4(), ipv4Packet.getDestinationIpv4()
					, udpPacket.getSrcPort(), udpPacket.getDstPort());
			Match match = reactiveFlowWriterPacketOut
					.creatUdpMatch(ipv4Packet.getSourceIpv4(), ipv4Packet.getDestinationIpv4(),
							udpPacket.getSrcPort(), udpPacket.getDstPort());
			Instructions instructions = null;
			if(Decision.DROP.equals(result)) {
				//1.匹配规则，结果为丢包。丢包，下发drop流表。
				reactiveFlowWriterPacketOut.dropingPacket(udpPacketReceived.getPayload());
				
				instructions = reactiveFlowWriterPacketOut.creatDropInstructions();
				Flow flow = reactiveFlowWriterPacketOut.creatFlow(match, instructions);
				reactiveFlowWriterPacketOut.writeFlowToSwitch(rawPacket.getIngress().getValue().firstKeyOf(Node.class).getId().getValue()
						,flow);
			}else {
				//2.匹配结果为转发。下发go to table流表，并packet out包到原switch。
				instructions = reactiveFlowWriterPacketOut.creatGoToTableInstructions();
				Flow flow = reactiveFlowWriterPacketOut.creatFlow(match, instructions);
				reactiveFlowWriterPacketOut.writeFlowToSwitch(rawPacket.getIngress().getValue().firstKeyOf(Node.class).getId().getValue()
						, flow);
//				try {
//					//try to finish flow entry installed before packet out the packet
//					Thread.sleep(1);
//				}catch (InterruptedException e) {
//					e.printStackTrace();
//				}
				reactiveFlowWriterPacketOut.packetOutPacket(udpPacketReceived.getPayload(), ethernetPacket.getDestinationMac());
			}
		}
		
		
		private void readUdpRulesFromConfig() {
								
				InstanceIdentifier<FirewallUdpRule> path = InstanceIdentifier.builder(FirewallRule.class)
						.child(FirewallUdpRule.class).build();
				ReadWriteTransaction trw = dataBroker.newReadWriteTransaction();
				Optional<FirewallUdpRule> rules = null;
				try {
					CheckedFuture<Optional<FirewallUdpRule>, ReadFailedException> future = 
							trw.read(LogicalDatastoreType.CONFIGURATION, path);
					rules = future.get();
					if(!rules.isPresent()) {
						//LOG.info("firewall-rules module data tree doesn't exist");
						FirewallUdpRuleBuilder builder = new FirewallUdpRuleBuilder();
						trw.put(LogicalDatastoreType.CONFIGURATION, path , builder.build());
						trw.submit().checkedGet();
						return;
					}
					
				}catch(InterruptedException | ExecutionException e) {
					LOG.warn("firewall-udp-rules module data tree doesn't exist");
				} catch (TransactionCommitFailedException e) {
					LOG.warn("Init firewall-udp-rules module data tree error");
				}
				udpRules = rules.get();
				
			
		}
		private Decision matchPacketWithRules(Ipv4Address srcIp, Ipv4Address dstIp, Integer srcPort, Integer dstPort) {
			Preconditions.checkNotNull(srcIp, "Source IP of packet should not be null");
			Preconditions.checkNotNull(dstIp, "Destination IP of packet should not be null");
			Preconditions.checkNotNull(srcPort, "Source PORT of packet should not be null");
			Preconditions.checkNotNull(dstPort, "Destination PORT of packet should not be null");
			readUdpRulesFromConfig();
			List<UdpRule> rules = null;
			// if no rules exist , the default action is forwarding it.
			if(udpRules == null || udpRules.getUdpRule() == null ) {
				return Decision.FORWARD;
			}
			rules = udpRules.getUdpRule();
			if(rules.size()==0) {
				return Decision.FORWARD;
			}
			rules.sort(new Comparator<UdpRule>() {
				@Override
				public int compare(UdpRule r1, UdpRule r2) {
					return r2.getPriority() - r1.getPriority();
				}
			});
			
			UdpRule matchedRule = null ;
			UdpRule rule = null;
			Iterator<UdpRule> it = rules.iterator();
			while(it.hasNext()) {
				rule = it.next();
				if((MatchUtil.matchPacketWithL3Rule(rule,srcIp,dstIp,srcPort,dstPort))){
					matchedRule = rule;
					break;
				}
			}
			
			// a rule was found and it was an "drop" rule
			if(matchedRule != null && matchedRule.getAction().getName().equals("drop")) {
				return Decision.DROP;
			}
						//a rule was found and it was an "allow" rule,
						//or, no rule was found, default decision is forwarding the packet;
			return Decision.FORWARD;
			
			
		}
	}
}
