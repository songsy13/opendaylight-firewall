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
import org.opendaylight.yang.gen.v1.urn.opendaylight.firewall.rules.db.rev180925.firewall.rule.FirewallIcmpRule;
import org.opendaylight.yang.gen.v1.urn.opendaylight.firewall.rules.db.rev180925.firewall.rule.FirewallIcmpRuleBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.firewall.rules.db.rev180925.firewall.rule.firewall.icmp.rule.IcmpRule;
import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.inventory.rev130819.tables.table.Flow;
import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.service.rev130819.SalFlowService;
import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.types.rev131026.flow.Instructions;
import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.types.rev131026.flow.Match;
import org.opendaylight.yang.gen.v1.urn.opendaylight.inventory.rev130819.NodeConnectorRef;
import org.opendaylight.yang.gen.v1.urn.opendaylight.inventory.rev130819.nodes.Node;
import org.opendaylight.yang.gen.v1.urn.opendaylight.packet.basepacket.rev140528.packet.chain.grp.PacketChain;
import org.opendaylight.yang.gen.v1.urn.opendaylight.packet.basepacket.rev140528.packet.chain.grp.packet.chain.packet.RawPacket;
import org.opendaylight.yang.gen.v1.urn.opendaylight.packet.ethernet.rev140528.ethernet.packet.received.packet.chain.packet.EthernetPacket;
import org.opendaylight.yang.gen.v1.urn.opendaylight.packet.icmp.rev140528.IcmpPacketListener;
import org.opendaylight.yang.gen.v1.urn.opendaylight.packet.icmp.rev140528.IcmpPacketReceived;
import org.opendaylight.yang.gen.v1.urn.opendaylight.packet.icmp.rev140528.icmp.packet.received.packet.chain.packet.IcmpPacket;
import org.opendaylight.yang.gen.v1.urn.opendaylight.packet.ipv4.rev140528.ipv4.packet.received.packet.chain.packet.Ipv4Packet;
import org.opendaylight.yang.gen.v1.urn.opendaylight.packet.service.rev130709.PacketProcessingService;

import org.opendaylight.yangtools.yang.binding.InstanceIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Optional;
import com.google.common.base.Preconditions;
import com.google.common.util.concurrent.CheckedFuture;


public class IcmpPacketProcesser implements IcmpPacketListener {
	private static final Logger LOG = LoggerFactory.getLogger(IcmpPacketProcesser.class);
	private static final int CPUS = Runtime.getRuntime().availableProcessors();
	private final ExecutorService executor = Executors.newFixedThreadPool(CPUS);
	
	private final DataBroker dataBroker;
	private final PacketProcessingService packetProcessingService;
	private final SalFlowService salFlowService;
	private final ReactiveFlowConfig reactiveFlowConfig;
	private ReactiveFlowWriterPacketOut reactiveFlowWriterPacketOut;
	
	
	

	public IcmpPacketProcesser(DataBroker dataBroker, PacketProcessingService packetProcessingService,
			SalFlowService salFlowService, ReactiveFlowConfig reactiveFlowConfig) {
		//super();
		this.dataBroker = dataBroker;
		this.packetProcessingService = packetProcessingService;
		this.salFlowService = salFlowService;
		this.reactiveFlowConfig = reactiveFlowConfig;
	}
	
	public void init() {
		LOG.info("IcmpListener initialized; Dispatcher a ReactiveFlowWriter to IcmpPacketProcessor");
		this.reactiveFlowWriterPacketOut = new ReactiveFlowWriterPacketOut(salFlowService,packetProcessingService,reactiveFlowConfig,dataBroker);
	}
	public void close() {
		LOG.info("IcmpListener shut down");
	}
	

	@Override
	public void onIcmpPacketReceived(IcmpPacketReceived icmpPacketReceived) {
		// TODO Auto-generated method stub
		LOG.info("Receive a ICMP packet");
		if(icmpPacketReceived == null || icmpPacketReceived.getPacketChain() == null)
			return ;
		
		RawPacket rawPacket = null ;
		EthernetPacket ethernetPacket = null ;
		Ipv4Packet ipv4Packet = null ;
		IcmpPacket icmpPacket = null;
		
		 for(PacketChain packetChain : icmpPacketReceived.getPacketChain()) {
				if (packetChain.getPacket() instanceof RawPacket) {
	               rawPacket = (RawPacket) packetChain.getPacket();
	            } else if (packetChain.getPacket() instanceof EthernetPacket) {
	               ethernetPacket = (EthernetPacket) packetChain.getPacket();
	            } else if (packetChain.getPacket() instanceof Ipv4Packet) {
	               ipv4Packet = (Ipv4Packet) packetChain.getPacket();
	            } else if (packetChain.getPacket() instanceof IcmpPacket) {
	            	icmpPacket = (IcmpPacket) packetChain.getPacket();
	            }
		 }
		 
		 if(rawPacket == null || ethernetPacket == null || ipv4Packet == null ||icmpPacket == null) {
			 return;
		 }
		 
		 executor.submit(new PacketProcessing(icmpPacketReceived, rawPacket,ethernetPacket, ipv4Packet, icmpPacket));
		
	}
	
	private class PacketProcessing implements Runnable{
		
		private FirewallIcmpRule icmpRules;
		private final IcmpPacketReceived icmpPacketReceived;
		private final RawPacket rawPacket  ;
		private final EthernetPacket ethernetPacket;
		private final Ipv4Packet ipv4Packet ;
		private final IcmpPacket icmpPacket ;
		
		
		
		public PacketProcessing(IcmpPacketReceived icmpPacketReceived, RawPacket rawPacket,
				EthernetPacket ethernetPacket, Ipv4Packet ipv4Packet,
				IcmpPacket icmpPacket) {
			super();
			this.icmpPacketReceived = icmpPacketReceived;
			this.rawPacket = rawPacket;
			this.ethernetPacket = ethernetPacket;
			this.ipv4Packet = ipv4Packet;
			this.icmpPacket = icmpPacket;
		}



		@Override
		public void run() {
			Decision result = matchPacketWithRules(ipv4Packet.getSourceIpv4(), ipv4Packet.getDestinationIpv4(),
					icmpPacket.getType(), icmpPacket.getCode());
			Match match = reactiveFlowWriterPacketOut
					.creatIcmpMatch(ipv4Packet.getSourceIpv4(), ipv4Packet.getDestinationIpv4(),
							icmpPacket.getType(), icmpPacket.getCode());
			Instructions instructions = null;
			if(Decision.DROP.equals(result)) {
				reactiveFlowWriterPacketOut.dropingPacket(icmpPacketReceived.getPayload());
				instructions = reactiveFlowWriterPacketOut.creatDropInstructions();
				Flow flow = reactiveFlowWriterPacketOut.creatFlow(match, instructions);
				reactiveFlowWriterPacketOut.writeFlowToSwitch(
						rawPacket.getIngress().getValue().firstKeyOf(Node.class).getId().getValue()
						,flow);				
				}else {
					instructions = reactiveFlowWriterPacketOut.creatGoToTableInstructions();
					Flow flow = reactiveFlowWriterPacketOut.creatFlow(match, instructions);
					reactiveFlowWriterPacketOut.writeFlowToSwitch(rawPacket.getIngress().getValue().firstKeyOf(Node.class).getId().getValue()
							, flow);
					reactiveFlowWriterPacketOut.packetOutPacket(icmpPacketReceived.getPayload(), ethernetPacket.getDestinationMac());
				}	
		}
		
		private void readIcmpRulesFromConfig() {
			InstanceIdentifier<FirewallIcmpRule> path = InstanceIdentifier.builder(FirewallRule.class)
					.child(FirewallIcmpRule.class).build();
			ReadWriteTransaction trw = dataBroker.newReadWriteTransaction();
			Optional<FirewallIcmpRule> rules = null;
			
			
			CheckedFuture<Optional<FirewallIcmpRule>, ReadFailedException> future = 
					trw.read(LogicalDatastoreType.CONFIGURATION, path);
			try {
				rules = future.get();
				if(!rules.isPresent()) {
					FirewallIcmpRuleBuilder builder = new FirewallIcmpRuleBuilder();
					trw.put(LogicalDatastoreType.CONFIGURATION, path, builder.build());
					trw.submit().checkedGet();
					return;
				}
			} catch (InterruptedException | ExecutionException e) {
				// TODO Auto-generated catch block
				LOG.warn("firewall-icmp-rules module data tree doesn't exist");
			} catch (TransactionCommitFailedException e) {
				// TODO Auto-generated catch block
				LOG.warn("firewall-icmp-rules module data tree initialization error");
			}
			
			icmpRules = rules.get();
			
		}
		
		private Decision matchPacketWithRules(Ipv4Address srcIp, Ipv4Address dstIp, Short type, Short code) {
			Preconditions.checkNotNull(srcIp, "Source IP of icmp packet should not be null");
			Preconditions.checkNotNull(dstIp, "Destination IP of icmp packet should not be null");
			Preconditions.checkNotNull(type, "Type of icmp  packet should not be null");
			Preconditions.checkNotNull(code, "Code of icmp packet should not be null");
			
			readIcmpRulesFromConfig();
			List<IcmpRule> rules = null;
			if(icmpRules == null || icmpRules.getIcmpRule() == null) {
				return Decision.FORWARD;
			}
			rules = icmpRules.getIcmpRule();
			if(rules.size() == 0) {
				return Decision.FORWARD;
			}
			//按照优先级由高到低排列
			rules.sort(new Comparator<IcmpRule>() {
				@Override
				public int compare(IcmpRule r1, IcmpRule r2) {
					return r2.getPriority() - r1.getPriority();
				}
			});
			
			IcmpRule matchedRule = null;
			IcmpRule rule = null;
			Iterator<IcmpRule> it = rules.iterator();
			while(it.hasNext()) {
				rule = it.next();
				if((MatchUtil.matchPacketWithIcmpRule(rule, srcIp, dstIp, type, code))) {
					matchedRule = rule;
					break;
				}
			}
			
			if(matchedRule != null && matchedRule.getAction().getName().equals("drop")) {
				return Decision.DROP;
			}
			return Decision.FORWARD;	
		}
			
	}

}
