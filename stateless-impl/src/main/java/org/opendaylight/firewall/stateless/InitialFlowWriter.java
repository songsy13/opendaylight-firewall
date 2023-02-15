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
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicLong;

import javax.annotation.Nonnull;

import org.opendaylight.controller.md.sal.binding.api.DataBroker;
import org.opendaylight.controller.md.sal.binding.api.DataObjectModification;
import org.opendaylight.controller.md.sal.binding.api.DataTreeChangeListener;
import org.opendaylight.controller.md.sal.binding.api.DataTreeIdentifier;
import org.opendaylight.controller.md.sal.binding.api.DataTreeModification;
import org.opendaylight.controller.md.sal.binding.api.DataObjectModification.ModificationType;
import org.opendaylight.controller.md.sal.common.api.data.LogicalDatastoreType;
import org.opendaylight.yang.gen.v1.urn.ietf.params.xml.ns.yang.ietf.inet.types.rev130715.IpVersion;
import org.opendaylight.yang.gen.v1.urn.ietf.params.xml.ns.yang.ietf.inet.types.rev130715.Uri;
import org.opendaylight.yang.gen.v1.urn.opendaylight.action.types.rev131112.action.action.OutputActionCaseBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.action.types.rev131112.action.action.output.action._case.OutputActionBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.action.types.rev131112.action.list.Action;
import org.opendaylight.yang.gen.v1.urn.opendaylight.action.types.rev131112.action.list.ActionBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.action.types.rev131112.action.list.ActionKey;
import org.opendaylight.yang.gen.v1.urn.opendaylight.firewall.rev180925.StatelessFirewallConfig;
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
import org.opendaylight.yang.gen.v1.urn.opendaylight.inventory.rev130819.NodeId;
import org.opendaylight.yang.gen.v1.urn.opendaylight.inventory.rev130819.NodeRef;
import org.opendaylight.yang.gen.v1.urn.opendaylight.inventory.rev130819.Nodes;
import org.opendaylight.yang.gen.v1.urn.opendaylight.inventory.rev130819.nodes.Node;
import org.opendaylight.yang.gen.v1.urn.opendaylight.inventory.rev130819.nodes.NodeKey;
import org.opendaylight.yang.gen.v1.urn.opendaylight.l2.types.rev130827.EtherType;
import org.opendaylight.yang.gen.v1.urn.opendaylight.model.match.types.rev131026.ethernet.match.fields.EthernetTypeBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.model.match.types.rev131026.match.EthernetMatch;
import org.opendaylight.yang.gen.v1.urn.opendaylight.model.match.types.rev131026.match.EthernetMatchBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.model.match.types.rev131026.match.IpMatch;
import org.opendaylight.yang.gen.v1.urn.opendaylight.model.match.types.rev131026.match.IpMatchBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.packet.ethernet.rev140528.KnownEtherType;
import org.opendaylight.yangtools.concepts.ListenerRegistration;
import org.opendaylight.yangtools.yang.binding.InstanceIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ImmutableList;

/**
 * Adds a flow, which sends UDP/ICMP packets which didn't match with existing rule2flow flow entries 
 * to the controller,on all switches
 * Registers ad ODL inventory listener so that it can add flows once a new node is added
 */
public class InitialFlowWriter implements DataTreeChangeListener<Node>{
private static final Logger LOG = LoggerFactory.getLogger(InitialFlowWriter.class);
	
	private final ExecutorService initialFlowExecutor = Executors.newCachedThreadPool();
	private final DataBroker dataBroker;
	private final SalFlowService salFlowService;
	private final StatelessFirewallConfig firewallConfig;
	
	private  ListenerRegistration<InitialFlowWriter> topoNodeListenerReg;
	
	private boolean firewallServiceEnable;
	
	private short udpFlowTableId;
	private int udpFlowHardTimeout;
	private int udpFlowIdleTimeout;
	private int udpFlowPriority;
	
	private short icmpFlowTableId;
	private int icmpFlowHardTimeout;
	private int icmpFlowIdleTimeout;
	private int icmpFlowPriority;
	
	private short goToTableFlowTableId;
	private int goToTableFlowHardTimeout;
	private int goToTableFlowIdleTimeout;
	private int goToTableFlowPriority;
	
	private AtomicLong flowIdInc = new AtomicLong();
    private AtomicLong flowCookieInc = new AtomicLong(0x2c00000000000000L);
	
    public InitialFlowWriter(DataBroker dataBroker, SalFlowService salFlowService, StatelessFirewallConfig firewallConfig) {
		this.dataBroker = dataBroker;
		this.salFlowService = salFlowService;
		this.firewallConfig = firewallConfig;
	}
    public void init() {
    	this.firewallServiceEnable = firewallConfig.isStatelessFirewallServiceEnabled();
    	this.udpFlowHardTimeout = firewallConfig.getUdpFlowHardTimeout();
    	this.udpFlowIdleTimeout = firewallConfig.getUdpFlowIdleTimeout();
    	this.udpFlowTableId = firewallConfig.getUdpFlowTableId();
    	this.udpFlowPriority = firewallConfig.getUdpFlowPriority();
    	
    	this.icmpFlowHardTimeout = firewallConfig.getIcmpFlowHardTimeout();
    	this.icmpFlowIdleTimeout = firewallConfig.getIcmpFlowIdleTimeout();
    	this.icmpFlowPriority = firewallConfig.getIcmpFlowPriority();
    	this.icmpFlowTableId = firewallConfig.getIcmpFlowTableId();
    	
    	this.goToTableFlowHardTimeout = firewallConfig.getGototableFlowHardTimeout();
    	this.goToTableFlowIdleTimeout = firewallConfig.getGototableFlowIdleTimeout();
    	this.goToTableFlowTableId = firewallConfig.getGototableFlowTableId();
    	this.goToTableFlowPriority = firewallConfig.getGototableFlowPriority();
    	
    	if(firewallServiceEnable) {
    		registerAsSwitchChangeListener();
			LOG.info("UDP/ICMP initial flow writer was initialized");
    	}
    	
    }
    public void close() {
    	if(topoNodeListenerReg!=null) {
    		topoNodeListenerReg.close();
    	}
	}
	public void registerAsSwitchChangeListener(){
		InstanceIdentifier<Node> nodeInstanceIdentifier = InstanceIdentifier.builder(Nodes.class)
                .child(Node.class).build();
		topoNodeListenerReg = dataBroker.registerDataTreeChangeListener(
				new DataTreeIdentifier<Node>(LogicalDatastoreType.OPERATIONAL, nodeInstanceIdentifier),
				this);
	}
	

	@Override
	public void onDataTreeChanged(@Nonnull Collection<DataTreeModification<Node>> changes) {
		Set<String> nodes = new HashSet<String>();
		for(final DataTreeModification<Node> change:changes) {
			DataObjectModification<Node> rootNode = change.getRootNode();
			if(rootNode.getModificationType()!=null && rootNode.getModificationType().equals(ModificationType.WRITE) ) {
				String nodeId = rootNode.getDataAfter().getId().getValue();
				if(nodeId.contains("openflow:")) {
					LOG.info("A new switch {} has been connected",nodeId);
					nodes.add(nodeId);
				}
			}
		}
		if(nodes != null && !nodes.isEmpty()) {
			initialFlowExecutor.submit(new InitialFlowWriterProcessor(nodes));
		}
		
	}
	
	private class InitialFlowWriterProcessor implements Runnable{
		private Set<String> nodes ;
		
		public InitialFlowWriterProcessor(Set<String> nodes) {
			this.nodes = nodes;
		}
		
		@Override
		public void run() {
			if(nodes == null) {
				return;
			}
			for(String node:nodes) {
				//addInitialFlow(node);
				addInitialUdpFlow(node);
				addInitialIcmpFlow(node);
				addInitialGoToTableFlow(node);
			}
		}
		
		public void addInitialUdpFlow(String node) {
			writeFlowToSwitch(node, 
					creatToControllerFlow(udpFlowTableId, (short)17, udpFlowPriority, udpFlowHardTimeout, udpFlowIdleTimeout), 
					udpFlowTableId);
			LOG.info("Added udp to CONTROLLER flow for node {}", node);
			
		}
		
		public void addInitialIcmpFlow(String node) {
			
			writeFlowToSwitch(node, 
					creatToControllerFlow(icmpFlowTableId, (short)1, icmpFlowPriority, icmpFlowHardTimeout, icmpFlowIdleTimeout), 
					icmpFlowTableId);
			LOG.info("Added icmp to CONTROLLER flow for node {}", node);
//			
		}
		
		public void addInitialGoToTableFlow(String node) {
			writeFlowToSwitch(node, 
					creatGoToTableFLow(goToTableFlowTableId, goToTableFlowPriority, goToTableFlowHardTimeout, goToTableFlowIdleTimeout),
					goToTableFlowTableId);
			LOG.info("Added go-to-table flow for node {}", node);
		}
		
		private Flow creatGoToTableFLow(Short tableId, int priority, int hardTimeout, int idleTimeout) {
			FlowBuilder flowBuilder = new FlowBuilder();
			flowBuilder.setTableId(tableId)//
			.setFlowName("gototable") //
			.setId(new FlowId(Long.toString(flowBuilder.hashCode())));
			Match match = new MatchBuilder().build();
			
			Instruction goToTableInstruction = new InstructionBuilder() //
					.setOrder(0) //
					.setInstruction(new GoToTableCaseBuilder()//
							.setGoToTable(new GoToTableBuilder().setTableId((short)1).build())//
							.build())
					.build();
			List<Instruction> instructions = new ArrayList<>();
			instructions.add(goToTableInstruction);
			
			flowBuilder
					.setMatch(match)//
					.setInstructions(new InstructionsBuilder()//
							.setInstruction(ImmutableList.copyOf(instructions))//
							.build())
					.setPriority(priority) //
		            .setBufferId(0xffffffffL) //
		            .setHardTimeout(hardTimeout) //
		            .setIdleTimeout(idleTimeout) //
		            .setCookie(new FlowCookie(BigInteger.valueOf(flowCookieInc.getAndIncrement())))
		            .setFlags(new FlowModFlags(false, false, false, false, false));
			return flowBuilder.build();
		}
		
		//ipProcotol: icmp,1  udp,17
		private Flow creatToControllerFlow(Short tableId, short ipProtocol, int priority, int hardTimeout, int idleTimeout) {
			FlowBuilder flowBuilder = new FlowBuilder();
			flowBuilder.setTableId(tableId)//
			.setFlowName("udp/icmp2cntrl") // 
			.setId(new FlowId(Long.toString(flowBuilder.hashCode())));// use its own hash code for id.
			
			//set two match fields: ethernetMatch:ethernetType="ipv4" , ipMatch:ipProtocol=6, ipProto="ipv4"
			EthernetMatch ethernetMatch = new EthernetMatchBuilder()
					.setEthernetType(new EthernetTypeBuilder()
							.setType(new EtherType(Long.valueOf(KnownEtherType.Ipv4.getIntValue())))
							.build()).build();
			IpMatch ipMatch = new IpMatchBuilder()
					.setIpProtocol(ipProtocol)
					.setIpProto(IpVersion.Ipv4).build();
			Match match = new MatchBuilder()
					.setEthernetMatch(ethernetMatch).setIpMatch(ipMatch).build();
			
			List<Action> actions = new ArrayList<Action>();
			actions.add(getSendToControllerAction());
			
			// Create an Apply Action
			ApplyActions applyActions = new ApplyActionsBuilder() //
					.setAction(ImmutableList.copyOf(actions)).build();
			
			// Wrap our Apply Action in an Instruction
            Instruction applyActionsInstruction = new InstructionBuilder() //
                    .setOrder(0)
                    .setInstruction(new ApplyActionsCaseBuilder()//
                            .setApplyActions(applyActions) //
                            .build()) //
                    .build();
            
            flowBuilder.setMatch(match)//
            .setInstructions(new InstructionsBuilder() //
            		.setInstruction(ImmutableList.of(applyActionsInstruction)) //
            		.build()) //
            .setPriority(priority) //
            .setBufferId(0xffffffffL) //
            .setHardTimeout(hardTimeout) //
            .setIdleTimeout(idleTimeout) //
            .setCookie(new FlowCookie(BigInteger.valueOf(flowCookieInc.getAndIncrement())))
            .setFlags(new FlowModFlags(false, false, false, false, false));
            
            return flowBuilder.build();
			
		}
		 private Action getSendToControllerAction() {
	            Action sendToController = new ActionBuilder()
	                    .setOrder(0)
	                    .setKey(new ActionKey(0))
	                    .setAction(new OutputActionCaseBuilder()
	                            .setOutputAction(new OutputActionBuilder()
	                                    .setMaxLength(0xffff)
	                                    .setOutputNodeConnector(new Uri(OutputPortValues.CONTROLLER.toString()))
	                                    .build())
	                            .build())
	                    .build();
	            return sendToController;
	     }
		 
		 private void writeFlowToSwitch(String nodeName, Flow flow, short flowTableId) {
			 final AddFlowInputBuilder builder = new AddFlowInputBuilder(flow);
			 final InstanceIdentifier<Node> nodeId = InstanceIdentifier.builder(Nodes.class)
						.child(Node.class, new NodeKey(new NodeId(nodeName)))
						.build();
			 final InstanceIdentifier<Table> tableId = nodeId.builder()
						.augmentation(FlowCapableNode.class)
						.child(Table.class, new TableKey(flowTableId))
						.build();
			 final InstanceIdentifier<Flow> flowId = tableId
					 .child(Flow.class, new FlowKey(new FlowId(flow.getFlowName())));
			 
			 builder.setNode(new NodeRef(nodeId));
			 builder.setFlowRef(new FlowRef(flowId));
			 builder.setFlowTable(new FlowTableRef(tableId));
			 builder.setTransactionUri(new Uri(flow.getId().getValue()));
			 
			 salFlowService.addFlow(builder.build());
					 
		 }

	}

	

}
