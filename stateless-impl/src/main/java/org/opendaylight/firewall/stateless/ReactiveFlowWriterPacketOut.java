/*
 * Copyright (c) 2018 Zhejiang University,Song Shuyu.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
package org.opendaylight.firewall.stateless;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

import org.opendaylight.controller.md.sal.binding.api.DataBroker;
import org.opendaylight.firewall.stateful.TopologyReader;
import org.opendaylight.yang.gen.v1.urn.ietf.params.xml.ns.yang.ietf.inet.types.rev130715.IpVersion;
import org.opendaylight.yang.gen.v1.urn.ietf.params.xml.ns.yang.ietf.inet.types.rev130715.Ipv4Address;
import org.opendaylight.yang.gen.v1.urn.ietf.params.xml.ns.yang.ietf.inet.types.rev130715.Ipv4Prefix;
import org.opendaylight.yang.gen.v1.urn.ietf.params.xml.ns.yang.ietf.inet.types.rev130715.PortNumber;
import org.opendaylight.yang.gen.v1.urn.ietf.params.xml.ns.yang.ietf.inet.types.rev130715.Uri;
import org.opendaylight.yang.gen.v1.urn.ietf.params.xml.ns.yang.ietf.yang.types.rev130715.MacAddress;
import org.opendaylight.yang.gen.v1.urn.opendaylight.action.types.rev131112.action.action.DropActionCaseBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.action.types.rev131112.action.action.OutputActionCaseBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.action.types.rev131112.action.action.drop.action._case.DropActionBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.action.types.rev131112.action.action.output.action._case.OutputActionBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.action.types.rev131112.action.list.Action;
import org.opendaylight.yang.gen.v1.urn.opendaylight.action.types.rev131112.action.list.ActionBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.firewall.rev180925.ReactiveFlowConfig;
import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.inventory.rev130819.FlowCapableNode;
import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.inventory.rev130819.FlowId;
import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.inventory.rev130819.tables.Table;
import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.inventory.rev130819.tables.TableKey;
import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.inventory.rev130819.tables.table.Flow;
import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.inventory.rev130819.tables.table.FlowBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.inventory.rev130819.tables.table.FlowKey;
import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.service.rev130819.AddFlowInputBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.service.rev130819.FlowTableRef;
import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.service.rev130819.SalFlowService;
import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.types.rev131026.FlowCookie;
import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.types.rev131026.FlowModFlags;
import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.types.rev131026.FlowRef;
import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.types.rev131026.OutputPortValues;
import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.types.rev131026.flow.Instructions;
import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.types.rev131026.flow.InstructionsBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.types.rev131026.flow.Match;
import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.types.rev131026.flow.MatchBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.types.rev131026.instruction.instruction.ApplyActionsCaseBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.types.rev131026.instruction.instruction.GoToTableCaseBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.types.rev131026.instruction.instruction.apply.actions._case.ApplyActions;
import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.types.rev131026.instruction.instruction.apply.actions._case.ApplyActionsBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.types.rev131026.instruction.instruction.go.to.table._case.GoToTableBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.types.rev131026.instruction.list.Instruction;
import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.types.rev131026.instruction.list.InstructionBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.inventory.rev130819.NodeConnectorRef;
import org.opendaylight.yang.gen.v1.urn.opendaylight.inventory.rev130819.NodeId;
import org.opendaylight.yang.gen.v1.urn.opendaylight.inventory.rev130819.NodeRef;
import org.opendaylight.yang.gen.v1.urn.opendaylight.inventory.rev130819.Nodes;
import org.opendaylight.yang.gen.v1.urn.opendaylight.inventory.rev130819.nodes.Node;
import org.opendaylight.yang.gen.v1.urn.opendaylight.inventory.rev130819.nodes.NodeKey;
import org.opendaylight.yang.gen.v1.urn.opendaylight.l2.types.rev130827.EtherType;
import org.opendaylight.yang.gen.v1.urn.opendaylight.model.match.types.rev131026.ethernet.match.fields.EthernetTypeBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.model.match.types.rev131026.match.EthernetMatch;
import org.opendaylight.yang.gen.v1.urn.opendaylight.model.match.types.rev131026.match.EthernetMatchBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.model.match.types.rev131026.match.Icmpv4Match;
import org.opendaylight.yang.gen.v1.urn.opendaylight.model.match.types.rev131026.match.Icmpv4MatchBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.model.match.types.rev131026.match.IpMatch;
import org.opendaylight.yang.gen.v1.urn.opendaylight.model.match.types.rev131026.match.IpMatchBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.model.match.types.rev131026.match.layer._3.match.Ipv4Match;
import org.opendaylight.yang.gen.v1.urn.opendaylight.model.match.types.rev131026.match.layer._3.match.Ipv4MatchBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.model.match.types.rev131026.match.layer._4.match.UdpMatch;
import org.opendaylight.yang.gen.v1.urn.opendaylight.model.match.types.rev131026.match.layer._4.match.UdpMatchBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.packet.ethernet.rev140528.KnownEtherType;
import org.opendaylight.yang.gen.v1.urn.opendaylight.packet.service.rev130709.PacketProcessingService;
import org.opendaylight.yang.gen.v1.urn.opendaylight.packet.service.rev130709.TransmitPacketInput;
import org.opendaylight.yang.gen.v1.urn.opendaylight.packet.service.rev130709.TransmitPacketInputBuilder;
import org.opendaylight.yangtools.yang.binding.InstanceIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;

public class ReactiveFlowWriterPacketOut {
	private static final Logger LOG = LoggerFactory.getLogger(ReactiveFlowWriterPacketOut.class);
	private final String FLOW_ID_PREFIX = "FWrule-";
	private final SalFlowService salFlowService;
	private final PacketProcessingService packetProcessingService;
	private final ReactiveFlowConfig reactiveFlowConfig;
	private final DataBroker dataBroker;
	
	private TopologyReader topologyReader;
	
	private short flowTableId;
	private int flowIdleTimeout;
	private int flowHardTimeout;
	private int flowPriority;
	
	private AtomicLong flowIdInc = new AtomicLong();
    private Long flowCookie = 0x0L;

    public ReactiveFlowWriterPacketOut(SalFlowService salFlowService,PacketProcessingService packetProcessingService, 
    		ReactiveFlowConfig reactiveFlowConfig, DataBroker dataBroker) {
        Preconditions.checkNotNull(salFlowService, "salFlowService should not be null.");
        Preconditions.checkNotNull(reactiveFlowConfig, "reactiveFlowConfig should not be null.");
        Preconditions.checkNotNull(packetProcessingService, "packetProcessingService should not be null.");
        this.salFlowService = salFlowService;
        this.packetProcessingService = packetProcessingService;
        this.reactiveFlowConfig = reactiveFlowConfig;
        this.dataBroker = dataBroker;
        init();
        
    }
    public void init() {
    	topologyReader = new TopologyReader(dataBroker);
    	flowTableId = reactiveFlowConfig.getReactiveFlowTableId();
    	flowIdleTimeout = reactiveFlowConfig.getReactiveFlowIdleTimeout();
    	flowHardTimeout = reactiveFlowConfig.getReactiveFlowHardTimeout();
    	flowPriority = reactiveFlowConfig.getReactiveFlowPriority();
    }
    
    public void writeFlowToSwitch(String nodeName, Flow flow) {
    	final AddFlowInputBuilder builder = new AddFlowInputBuilder(flow);
		 final InstanceIdentifier<Node> nodeId = InstanceIdentifier.builder(Nodes.class)
					.child(Node.class, new NodeKey(new NodeId(nodeName)))
					.build();
		 final InstanceIdentifier<Table> tableId = nodeId.builder()
					.augmentation(FlowCapableNode.class)
					.child(Table.class, new TableKey(flowTableId))
					.build();
		 final InstanceIdentifier<Flow> flowId = tableId
				 .child(Flow.class, new FlowKey(
						 new FlowId(FLOW_ID_PREFIX + String.valueOf(flowIdInc.getAndIncrement()))));
		 
		 builder.setNode(new NodeRef(nodeId));
		 builder.setFlowRef(new FlowRef(flowId));
		 builder.setFlowTable(new FlowTableRef(tableId));
		 builder.setTransactionUri(new Uri(flow.getId().getValue()));
		 
		 salFlowService.addFlow(builder.build());
    } 
    
    public Flow creatFlow( Match match, Instructions instruction) {
    	FlowBuilder flowBuilder = new FlowBuilder();
    	flowBuilder.setTableId(reactiveFlowConfig.getReactiveFlowTableId()) //
    	.setFlowName("rule2flow") //
    	.setId(new FlowId(Long.toString(flowBuilder.hashCode())));
    	
    	flowBuilder.setMatch(match) //
    		.setInstructions(instruction) //
    		.setPriority(flowPriority) //
    		.setBufferId(0xffffffffL) //
    		.setHardTimeout(flowHardTimeout) //
    		.setIdleTimeout(flowIdleTimeout) //
    		.setCookie(new FlowCookie(BigInteger.valueOf(flowCookie)))
    		.setFlags(new FlowModFlags(true, false, false, false, false));
    	return flowBuilder.build();
    }
    	public Match creatIcmpMatch(Ipv4Address srcIp, Ipv4Address dstIp, Short type, Short code) {
    		EthernetMatch ethernetMatch = new EthernetMatchBuilder()
					.setEthernetType(new EthernetTypeBuilder()
							.setType(new EtherType(Long.valueOf(KnownEtherType.Ipv4.getIntValue())))
							.build()).build();
    		IpMatch ipMatch = new IpMatchBuilder()
    				.setIpProtocol((short)1)
    				.setIpProto(IpVersion.Ipv4)
    				.build();
    		Ipv4Match ipv4Match = new Ipv4MatchBuilder()
    				.setIpv4Source(convert(srcIp))
    				.setIpv4Destination(convert(dstIp))
    				.build();
    		Icmpv4Match icmpMatch = new Icmpv4MatchBuilder()
    				.setIcmpv4Code(code)
    				.setIcmpv4Type(type)
    				.build();
    		return new MatchBuilder()
    				.setEthernetMatch(ethernetMatch)
    				.setIpMatch(ipMatch)
    				.setLayer3Match(ipv4Match)
    				.setIcmpv4Match(icmpMatch)
    				.build();
    	}
    		
    	public Match creatUdpMatch(Ipv4Address srcIp, Ipv4Address dstIp, Integer srcPort ,Integer dstPort) {
    		
    		EthernetMatch ethernetMatch = new EthernetMatchBuilder()
					.setEthernetType(new EthernetTypeBuilder()
							.setType(new EtherType(Long.valueOf(KnownEtherType.Ipv4.getIntValue())))
							.build()).build();
    		IpMatch ipMatch = new IpMatchBuilder()
					.setIpProtocol((short)17)
					.setIpProto(IpVersion.Ipv4).build();
    		Ipv4Match ipv4Match = new Ipv4MatchBuilder()
    				.setIpv4Source(convert(srcIp))
    				.setIpv4Destination(convert(dstIp))
    				.build();
    		UdpMatch udpMatch = new UdpMatchBuilder()
    				.setUdpSourcePort(new PortNumber(srcPort))
    				.setUdpDestinationPort(new PortNumber(dstPort))
    				.build();
    		
    		return new MatchBuilder()
    				.setEthernetMatch(ethernetMatch)
    				.setIpMatch(ipMatch)
    				.setLayer3Match(ipv4Match)
    				.setLayer4Match(udpMatch)
    				.build();	
    	}
    	
    	public Instructions creatDropInstructions() {
    		Action dropAllAction = new ActionBuilder() //
                    .setOrder(0)
                    .setAction(new DropActionCaseBuilder().build())
                    .build();

            // Create an Apply Action
            ApplyActions applyActions = new ApplyActionsBuilder().setAction(ImmutableList.of(dropAllAction))
                    .build();

            // Wrap our Apply Action in an Instruction
            Instruction applyActionsInstruction = new InstructionBuilder() //
                    .setOrder(0)
                    .setInstruction(new ApplyActionsCaseBuilder()//
                            .setApplyActions(applyActions) //
                            .build()) //
                    .build();
            return new InstructionsBuilder()
            		.setInstruction(ImmutableList.of(applyActionsInstruction))
            		.build();
    	}
    	public Instructions creatGoToTableInstructions() {
    		Instruction goToTableInstruction = new InstructionBuilder() //
					.setOrder(0) //
					.setInstruction(new GoToTableCaseBuilder()//
							.setGoToTable(new GoToTableBuilder().setTableId((short)1).build())//
							.build())
					.build();
			List<Instruction> instructions = new ArrayList<>();
			instructions.add(goToTableInstruction);
			
			return new InstructionsBuilder()
					.setInstruction(ImmutableList.copyOf(instructions))
					.build();
    	}
    	
    	public void dropingPacket(byte[] payload) {
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
		public void packetOutPacket(byte[] payload, MacAddress dstMac) {
			NodeConnectorRef egress = topologyReader.getDstNodeConnectorRef(dstMac);
			if( egress == null ) {
				LOG.info("Cannot forward icmp/udp packet, as topology doesn't have matched node connector for destination MAC:{}",dstMac);;
				return;
			}
			InstanceIdentifier<Node> egressNodePath = egress.getValue().firstIdentifierOf(Node.class);
//			List<Action> action = new ArrayList<Action>();
//			
//			action.add(new ActionBuilder().setOrder(0)
//					.setAction(new OutputActionCaseBuilder()
//							.setOutputAction(new OutputActionBuilder()
//									.setOutputNodeConnector(new Uri(OutputPortValues.TABLE.toString()))
//									.setMaxLength(65535)
//									.build())
//							.build())
//					.build());
			
			TransmitPacketInput input = new TransmitPacketInputBuilder()//
					.setNode(new NodeRef(egressNodePath))
					.setEgress(egress)
					//.setAction(action)
					.setPayload(payload)
					.build();
			packetProcessingService.transmitPacket(input);
			
		}
		

    	
    	private Ipv4Prefix convert(Ipv4Address ip) {
    		String ipv4PrefixValue = ip.getValue() + "/32" ;
    		return new Ipv4Prefix(ipv4PrefixValue);
    	}
    	
    	
    	
    
	

}
