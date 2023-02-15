/*
 * Copyright (c) 2018 Zhejiang University,Song Shuyu.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

package org.opendaylight.firewall.stateful;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.opendaylight.controller.md.sal.binding.api.DataBroker;
import org.opendaylight.controller.md.sal.binding.api.ReadOnlyTransaction;
import org.opendaylight.controller.md.sal.binding.api.ReadWriteTransaction;
import org.opendaylight.controller.md.sal.common.api.data.LogicalDatastoreType;
import org.opendaylight.controller.md.sal.common.api.data.ReadFailedException;
import org.opendaylight.controller.md.sal.common.api.data.TransactionCommitFailedException;
import org.opendaylight.firewall.util.Decision;
import org.opendaylight.firewall.util.MatchUtil;
import org.opendaylight.yang.gen.v1.urn.ietf.params.xml.ns.yang.ietf.inet.types.rev130715.Ipv4Address;
import org.opendaylight.yang.gen.v1.urn.ietf.params.xml.ns.yang.ietf.yang.types.rev130715.MacAddress;
import org.opendaylight.yang.gen.v1.urn.opendaylight.action.types.rev131112.action.action.DropActionCaseBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.action.types.rev131112.action.action.drop.action._case.DropActionBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.action.types.rev131112.action.list.Action;
import org.opendaylight.yang.gen.v1.urn.opendaylight.action.types.rev131112.action.list.ActionBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.firewall.rev180925.StatefulFirewallConfig;
import org.opendaylight.yang.gen.v1.urn.opendaylight.firewall.rules.db.rev180925.FirewallRule;
import org.opendaylight.yang.gen.v1.urn.opendaylight.firewall.rules.db.rev180925.firewall.rule.FirewallTcpRule;
import org.opendaylight.yang.gen.v1.urn.opendaylight.firewall.rules.db.rev180925.firewall.rule.FirewallTcpRuleBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.firewall.rules.db.rev180925.firewall.rule.firewall.tcp.rule.TcpRule;
import org.opendaylight.yang.gen.v1.urn.opendaylight.firewall.rules.db.rev180925.l3.rule.MatchFields;
import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.service.rev130819.SalFlowService;
import org.opendaylight.yang.gen.v1.urn.opendaylight.inventory.rev130819.NodeConnectorRef;
import org.opendaylight.yang.gen.v1.urn.opendaylight.inventory.rev130819.NodeRef;
import org.opendaylight.yang.gen.v1.urn.opendaylight.inventory.rev130819.nodes.Node;
import org.opendaylight.yang.gen.v1.urn.opendaylight.packet.arp.rev140528.arp.packet.received.packet.chain.packet.ArpPacket;
import org.opendaylight.yang.gen.v1.urn.opendaylight.packet.basepacket.rev140528.packet.chain.grp.PacketChain;
import org.opendaylight.yang.gen.v1.urn.opendaylight.packet.basepacket.rev140528.packet.chain.grp.packet.chain.packet.RawPacket;
import org.opendaylight.yang.gen.v1.urn.opendaylight.packet.ethernet.rev140528.ethernet.packet.received.packet.chain.packet.EthernetPacket;
import org.opendaylight.yang.gen.v1.urn.opendaylight.packet.ipv4.rev140528.ipv4.packet.received.packet.chain.packet.Ipv4Packet;
import org.opendaylight.yang.gen.v1.urn.opendaylight.packet.ipv4.tcp.rev180925.TcpPacketListener;
import org.opendaylight.yang.gen.v1.urn.opendaylight.packet.ipv4.tcp.rev180925.TcpPacketReceived;
import org.opendaylight.yang.gen.v1.urn.opendaylight.packet.ipv4.tcp.rev180925.tcp.packet.received.packet.chain.packet.TcpPacket;
import org.opendaylight.yang.gen.v1.urn.opendaylight.packet.service.rev130709.PacketProcessingService;
import org.opendaylight.yang.gen.v1.urn.opendaylight.packet.service.rev130709.TransmitPacketInput;
import org.opendaylight.yang.gen.v1.urn.opendaylight.packet.service.rev130709.TransmitPacketInputBuilder;
import org.opendaylight.yangtools.yang.binding.InstanceIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Optional;
import com.google.common.util.concurrent.CheckedFuture;


public class TcpPacketProcessorProvider implements TcpPacketListener {
	
	private static final Logger LOG = LoggerFactory.getLogger(TcpPacketProcessorProvider.class);
	
	private static final int CPUS = Runtime.getRuntime().availableProcessors();
	private final ExecutorService executor = Executors.newFixedThreadPool(CPUS);
	private final Timer timer = new Timer();
	
	private final DataBroker dataBroker;
	private final StatefulFirewallConfig firewallConfig;
	private final PacketProcessingService packetProcessingService;
	private final SalFlowService salFlowService;
	
	private  TopologyReader topologyReader;
	private  InitialFlowWriter initialFlowWriter;
	private  List<ConnectionRecord> connectionList ;
	
	private enum State{
		SYN,ACK,FIN
	};
	
    public TcpPacketProcessorProvider(DataBroker dataBroker, PacketProcessingService packetProcessingService,
    		StatefulFirewallConfig firewallConfig, SalFlowService salFlowService) {
    	LOG.info("Start listening to TCP packets");
		this.dataBroker = dataBroker;
		this.packetProcessingService = packetProcessingService ;
		this.firewallConfig = firewallConfig;
		this.salFlowService = salFlowService;
		
		
	}
    
    public void init() {
    	if(!firewallConfig.isStatefulFirewallServiceEnabled()) {
    		return ;
    	}
    	LOG.info("Stateful firewall has been enabled, set up InitialFlowWriter and connection list ");
    	topologyReader = new TopologyReader(dataBroker);
    	initialFlowWriter = new InitialFlowWriter(dataBroker, salFlowService, firewallConfig);
    	initialFlowWriter.init();
    	connectionList = new LinkedList<ConnectionRecord>();
    	//check every single existing connection,
    	//  delete if no packet has been match in 1 minute; 
    	timer.schedule(new TimerTask() {
			
			@Override
			public void run() {
				synchronized (connectionList) {
					LOG.info("Current connection records table:{}",connectionList);
					Iterator<ConnectionRecord> it = connectionList.iterator();
					while(it.hasNext()) {
						ConnectionRecord data = it.next();
						Long currentTime = System.currentTimeMillis();
						if((currentTime - data.getLastTime()) > 60000) {
							it.remove();
						}
					}
				}
				
			}
		}, 1000, 50000);
    }
    public void close() {
    	initialFlowWriter.close();
    	timer.schedule(new TimerTask() {
			
			@Override
			public void run() {
				// TODO Auto-generated method stub
				timer.cancel();
			}
		}, 100);
    	LOG.info("TCP packet processing module closed");
    	executor.shutdown();
    	
    }
	

	@Override
	public void onTcpPacketReceived(TcpPacketReceived tcpPacketReceived) {
		//LOG.info("Receive a TCP packet");
		if(tcpPacketReceived == null || tcpPacketReceived.getPacketChain() == null ) {
			return;
		}
	   RawPacket rawPacket = null ;
	   EthernetPacket ethernetPacket = null ;
	   Ipv4Packet ipv4Packet = null ;
	   TcpPacket tcpPacket = null ;
		for(PacketChain packetChain : tcpPacketReceived.getPacketChain()) {
			if (packetChain.getPacket() instanceof RawPacket) {
               rawPacket = (RawPacket) packetChain.getPacket();
            } else if (packetChain.getPacket() instanceof EthernetPacket) {
               ethernetPacket = (EthernetPacket) packetChain.getPacket();
            } else if (packetChain.getPacket() instanceof Ipv4Packet) {
               ipv4Packet = (Ipv4Packet) packetChain.getPacket();
            } else if (packetChain.getPacket() instanceof TcpPacket) {
               tcpPacket = (TcpPacket) packetChain.getPacket();
            }
		}
			if(rawPacket == null || ethernetPacket == null || ipv4Packet == null || tcpPacket == null ) {
				return;
			}
			
		//LOG.info("Allocation a runnable object to process this packet");
		executor.submit(new packetProcessing(tcpPacketReceived, rawPacket, ethernetPacket, ipv4Packet, tcpPacket));		
	}
	
	
	//私有内部类只能够在外部类内部实例化？
	private class packetProcessing implements Runnable{
		
		private FirewallTcpRule firewallRules;
		private final TcpPacketReceived tcpPacketReceived ;
		private final RawPacket rawPacket  ;
		private final EthernetPacket ethernetPacket ;
		private final Ipv4Packet ipv4Packet ;
		private final TcpPacket tcpPacket  ;
		private boolean syn , ack, fin ;
		
		public packetProcessing(TcpPacketReceived tcpPacketReceived, RawPacket rawPacket, EthernetPacket ethernetPacket,
				Ipv4Packet ipv4Packet, TcpPacket tcpPacket) {
			this.tcpPacketReceived = tcpPacketReceived;
			this.rawPacket = rawPacket;
			this.ethernetPacket = ethernetPacket;
			this.ipv4Packet = ipv4Packet;
			this.tcpPacket = tcpPacket ;
		}
		
		private State checkFlag(){
			syn = tcpPacket.isSynFlag();
			ack = tcpPacket.isAckFlag();
			fin = tcpPacket.isFinFlag();
			if(syn && !ack) {
				return State.SYN;
			}else if(ack && !fin) {
				return State.ACK;
			}else if(fin) {
				return State.FIN;
			}
			return null;
		}
		
		private void forwardingPacket(NodeConnectorRef ingress, MacAddress dstMac, byte[] payload) {
			NodeConnectorRef egress = topologyReader.getDstNodeConnectorRef(dstMac);
			if( egress == null ) {
				LOG.info("Cannot forward packet, as topology doesn't have matched node connector for destination MAC:{}",dstMac);;
				return;
			}
			InstanceIdentifier<Node> egressNodePath = egress.getValue().firstIdentifierOf(Node.class);
			TransmitPacketInput input = new TransmitPacketInputBuilder()//
					.setPayload(payload)//
					.setNode(new NodeRef(egressNodePath))//
					.setEgress(egress)//
					//.setIngress(ingress)//
					.build();
			packetProcessingService.transmitPacket(input);
		}
		private void dropingPacket(byte[] payload) {
			List<Action> action = new ArrayList<Action>();
			action.add(new ActionBuilder().setOrder(0)
						    .setAction(new DropActionCaseBuilder()
							.setDropAction(new DropActionBuilder().build())
						 .build())
					   .build());
			TransmitPacketInput input = new TransmitPacketInputBuilder()//
					.setPayload(payload)
					.setAction(action)
					.build();
			packetProcessingService.transmitPacket(input);
		}
		private Decision matchACKandFINPacketWithConnectionRecords(Ipv4Address srcIp, Ipv4Address dstIp, Integer srcPort, Integer dstPort, State flag) {
			synchronized(connectionList) {
				if(connectionList.size()==0) {
					return Decision.DROP;
				}
				Iterator<ConnectionRecord> it = connectionList.iterator();
				while(it.hasNext()) {
					ConnectionRecord data = it.next();
					//ip与port双向匹配，因为连接是双向的
					if(( srcIp.getValue().equals(data.getSrcIp()) && 
							dstIp.getValue().equals(data.getDstIp()) &&
							srcPort.equals(data.getSrcPort()) &&
							dstPort.equals(data.getDstPort()) ) || 
						( srcIp.getValue().equals(data.getDstIp()) && 
								dstIp.getValue().equals(data.getSrcIp()) && 
								srcPort.equals(data.getDstPort()) &&
								dstPort.equals(data.getSrcPort()) )
					  ) {
						if(State.ACK.equals(flag)) {
							//ack包成功匹配该记录，记录匹配包数量加1,并更新时间戳
							data.addPacketCounter();
						}else if(State.FIN.equals(flag)) {
							//fin包成功匹配该记录
							if(data.getFinCounter() == 2 ) {
								//该连接第一次匹配到fin包,fincounter-1，记录该fin包的源ip，匹配包数量加1
								data.minusFinCounter();
								data.setFinDirection(srcIp.getValue());
								data.addPacketCounter();
							}else if(data.getFinCounter() == 1) {
								//该连接已经匹配过fin包
								//该fin包的源ip与之前相同，连接仍存在，接收方还没有回应
								if(data.getFinDirection().equals(srcIp.getValue())) {data.addPacketCounter();}
								//该fin包的目的ip与findirection相同，接收方回应，counter-1,除去该连接。
								else if(data.getFinDirection().equals(dstIp.getValue())) {
									data.minusFinCounter();
									if(data.getFinCounter() == 0 ) {it.remove();}
								}
							}
						}
						//不论是ACK包还是FIN包，匹配成功类，都需要先转发。
						return Decision.FORWARD;
					} 
				}
				//连接表遍历完成，没有找到匹配项，丢弃该包。
				return Decision.DROP;
				
			}
		}
		private void readStateRulesFromConfig() {
			synchronized(dataBroker) {
				InstanceIdentifier<FirewallTcpRule> path = InstanceIdentifier.builder(FirewallRule.class)
						.child(FirewallTcpRule.class).build();
				//InstanceIdentifier<FirewallRules> path = InstanceIdentifier.builder(FirewallRules.class).build();
				ReadWriteTransaction trw = dataBroker.newReadWriteTransaction();
				//ReadOnlyTransaction tr = dataBroker.newReadOnlyTransaction();
				Optional<FirewallTcpRule> rules = null;
				try {
					CheckedFuture<Optional<FirewallTcpRule>, ReadFailedException> future = 
							trw.read(LogicalDatastoreType.CONFIGURATION, path);
					rules = future.get();
					if(!rules.isPresent()) {
						//LOG.info("firewall-rules module data tree doesn't exist");
						FirewallTcpRuleBuilder builder = new FirewallTcpRuleBuilder();
						trw.put(LogicalDatastoreType.CONFIGURATION, path , builder.build());
						trw.submit().checkedGet();
						return;
					}
				}catch(InterruptedException | ExecutionException e) {
					LOG.warn("firewall-tcp-rules module data tree doesn't exist");
				} catch (TransactionCommitFailedException e) {
					LOG.warn("Init firewall-tcp-rules module data tree error");
				}
				firewallRules = rules.get();
			}
		}
		
		private Decision matchSYNPacketwithRules(Ipv4Address srcIp, Ipv4Address dstIp, Integer srcPort, Integer dstPort) {
			readStateRulesFromConfig();
//			Optional<List<FwStatefulRules>> optionRules = Optional.fromNullable(firewallRules.getFwStatefulRules());
//			if(!optionRules.isPresent()) {
//				return Decision.FORWARD;
//			}
			List<TcpRule> rules = null;
			if(firewallRules == null || firewallRules.getTcpRule() == null) {
				//default miss-matched action is forwarding.
				return Decision.FORWARD;
			}
			rules = firewallRules.getTcpRule();
			if(rules.size()==0) {
				return Decision.FORWARD;
			}

			// sort the list based on priorities
			//rules.sort(new PriorityComparator());
			rules.sort(new Comparator<TcpRule>() {
				@Override
				public int compare(TcpRule r1, TcpRule r2) {
					//按照优先级由高到低排列
					return r2.getPriority() - r1.getPriority();
				}
			});
			// hold the rule which the pkt matches 
			TcpRule matchedRule = null ;
			//find if a rule is matched
			
				Iterator<TcpRule> it = rules.iterator();
				TcpRule rule = null ;
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
//		private boolean matchPacketWithRule(TcpRule rule, 
//				Ipv4Address srcIp, Ipv4Address dstIp, Integer srcPort, Integer dstPort) {
//			//these four boolean values record match results of each field in rule;
//			boolean srcIpMatch = false , dstIpMatch = false, srcPortMatch = false, dstPortMatch = false;
//			LOG.info("match with rule {}",rule);
//			//wildcard field is regarded as matched with any value;
//			// if a field is not wildcard(null) , compare it with corresponding field of packet
//			Integer ruleSrcPort = null, ruleDstPort = null;
//			String  ruleSrcIp = null, ruleDstIp = null ;
//			if(java.util.Optional.of(rule)
//				.map(TcpRule::getMatchFields)
//				.map(MatchFields::getTcpSourcePort)
//				.isPresent()) {
//				ruleSrcPort = rule.getMatchFields().getTcpSourcePort().getValue();
//			}
//			if(java.util.Optional.of(rule)
//					.map(TcpRule::getMatchFields)
//					.map(MatchFields::getTcpDestinationPort)
//					.isPresent()) {
//					ruleDstPort = rule.getMatchFields().getTcpDestinationPort().getValue();
//			}
//			if(java.util.Optional.of(rule)
//					.map(TcpRule::getMatchFields)
//					.map(MatchFields::getIpSource)
//					.isPresent()) {
//					ruleSrcIp = rule.getMatchFields().getIpSource().getValue();
//			}
//			if(java.util.Optional.of(rule)
//					.map(TcpRule::getMatchFields)
//					.map(MatchFields::getIpDestination)
//					.isPresent()) {
//					ruleDstIp = rule.getMatchFields().getIpDestination().getValue();
//				}
//			
//			if(ruleSrcPort == null || 
//					ruleSrcPort.equals(srcPort)) {
//				srcPortMatch = true ;
//			}
//			if(ruleDstPort == null ||
//					ruleDstPort.equals(dstPort)) {
//				dstPortMatch = true ;
//			}
//			if(ruleSrcIp == null ||
//					match(ruleSrcIp,srcIp.getValue())) {
//				srcIpMatch = true ;
//			}
//			if(ruleDstIp == null ||
//					match(ruleDstIp,dstIp.getValue())) {
//				dstIpMatch = true ;
//			}
//			
//			return srcIpMatch && dstIpMatch && srcPortMatch && dstPortMatch ;
//			
//		}
//		/*
//		 * match ip(src and dest) of tcp packet with rule-ip with prefix;
//		 * @return true if the ip of tcp packet belong to the segment network specfied by rule-ip with prefix
//		 * 
//		 */
//		private boolean match(String ruleIp, String pktIp) {
//			String ruleIpNoMask = ruleIp.split("/")[0];
//			String mask = ruleIp.split("/")[1];
//			int ruleIp1int = to1Int(ruleIpNoMask);
//			int pktIp1int = to1Int(pktIp);
//			int maskToAndOperator = 0 ;
//			//convert the string mask to a 32 bits int ,for example:
//			// 24 = 0xfff0; 30 = b11111111111111111111111111111100;
//			for(int i=0;i<32;i++) {
//				if(i > (32 - Integer.parseInt(mask) - 1)) {
//					//1 << i == 2^i ;
//					maskToAndOperator += (1 << i);
//				}
//			}
//			return (ruleIp1int & maskToAndOperator ) == (pktIp1int & maskToAndOperator);
//			
//			
//		}
//		/*
//		 * convert the String ip to a 32 bits int
//		 * 1. split ip to 4 parts by the  regular expression "\\."
//		 * 2. cast string to int 
//		 * 3. join 4 int values by add and left shift operators , so that we can get a 32 bits int value
//		 */
//		private int to1Int(String ipNoMask) {
//			String[] parsedIP = ipNoMask.split("\\.");
//			int[] ip4int = new int[4];
//			for(int i=0;i<4;i++) {
//				ip4int[i] = Integer.parseInt(parsedIP[i]);
//			}
//			int i = (ip4int[0] << 24) //
//					+ (ip4int[1] << 16) //
//					+ (ip4int[2] << 8) //
//					+ (ip4int[3]) ;
//			return i ;
//		}

		@Override
		public void run() {
			
			State flag = checkFlag();
			LOG.info("Receive a {} packet",flag);
			//decode();
			//1.根据标志位判断连接状态
			if(State.SYN.equals(flag)) {
				//2.发起一条连接时，匹配规则，决定是否转发。
				if(Decision.FORWARD
						.equals(matchSYNPacketwithRules(ipv4Packet.getSourceIpv4(), ipv4Packet.getDestinationIpv4(),
						tcpPacket.getSrcPort(), tcpPacket.getDstPort()))) {
					//3.决定转发该数据包，在状态连接表中添加该连接记录
					forwardingPacket(rawPacket.getIngress(), ethernetPacket.getDestinationMac(), tcpPacketReceived.getPayload());
					synchronized(connectionList) {
						connectionList.add(new ConnectionRecord(ipv4Packet.getSourceIpv4().getValue(),
								ipv4Packet.getDestinationIpv4().getValue(), tcpPacket.getSrcPort(), tcpPacket.getDstPort()));
						LOG.info("Add a connection record: srcIP:{}, dstIP:{}, srcPort:{}, dstPort{} ",
								ipv4Packet.getSourceIpv4().getValue(),ipv4Packet.getDestinationIpv4().getValue(),
								tcpPacket.getSrcPort(), tcpPacket.getDstPort());
					}
				}
				//4.匹配规则结果为Drop,丢弃该数据包
				else {
					dropingPacket(tcpPacketReceived.getPayload());
				}
			}else if(State.ACK.equals(flag) || State.FIN.equals(flag)) {
				//2.不是新的连接，匹配状态连接表，决定是否转发
				if(Decision.FORWARD
						.equals(matchACKandFINPacketWithConnectionRecords(ipv4Packet.getSourceIpv4(), ipv4Packet.getDestinationIpv4(),
						tcpPacket.getSrcPort(), tcpPacket.getDstPort(), flag ))) {
					//3. 转发该数据包
					forwardingPacket(rawPacket.getIngress(), ethernetPacket.getDestinationMac(), tcpPacketReceived.getPayload());
				}else {
					dropingPacket(tcpPacketReceived.getPayload());
				}
			}else {
				dropingPacket(tcpPacketReceived.getPayload());
			}
		}
		
	}
	//静态内部类只能访问外部类的静态域，因此当内部类不需要访问外部类的私有域时，可以声明为静态
//	private static class PriorityComparator implements Comparator<FwStatefulRules>{
//
//		@Override
//		public int compare(FwStatefulRules r1, FwStatefulRules r2) {
//			//按照优先级由高到低排列
//			return r2.getPriority() - r1.getPriority();
//		}
//		
//	}

	
	

}
