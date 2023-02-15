/*
 * Copyright (c) 2018 Zhejiang University,Song Shuyu.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


package org.opendaylight.firewall.stateful;

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
import org.opendaylight.controller.md.sal.binding.api.DataObjectModification.ModificationType;
import org.opendaylight.controller.md.sal.binding.api.DataTreeChangeListener;
import org.opendaylight.controller.md.sal.binding.api.DataTreeIdentifier;
import org.opendaylight.controller.md.sal.binding.api.DataTreeModification;
import org.opendaylight.controller.md.sal.common.api.data.LogicalDatastoreType;
import org.opendaylight.yang.gen.v1.urn.ietf.params.xml.ns.yang.ietf.inet.types.rev130715.IpVersion;
import org.opendaylight.yang.gen.v1.urn.ietf.params.xml.ns.yang.ietf.inet.types.rev130715.Uri;
import org.opendaylight.yang.gen.v1.urn.opendaylight.action.types.rev131112.action.action.OutputActionCaseBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.action.types.rev131112.action.action.output.action._case.OutputActionBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.action.types.rev131112.action.list.Action;
import org.opendaylight.yang.gen.v1.urn.opendaylight.action.types.rev131112.action.list.ActionBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.action.types.rev131112.action.list.ActionKey;
import org.opendaylight.yang.gen.v1.urn.opendaylight.firewall.rev180925.StatefulFirewallConfig;
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
import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.types.rev131026.instruction.instruction.apply.actions._case.ApplyActions;
import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.types.rev131026.instruction.instruction.apply.actions._case.ApplyActionsBuilder;
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
 * Adds a flow, which sends all TCP packets to the controller,on all switches
 * Registers ad ODL inventory listener so that it can add flows once a new node is added
 */
public class InitialFlowWriter implements DataTreeChangeListener<Node>{
	private static final Logger LOG = LoggerFactory.getLogger(InitialFlowWriter.class);
	
	private final ExecutorService initialFlowExecutor = Executors.newCachedThreadPool();
	private final DataBroker dataBroker;
	private  ListenerRegistration<InitialFlowWriter> topoNodeListenerReg;
	private final SalFlowService salFlowService;
	private final StatefulFirewallConfig firewallConfig;
	
	private boolean firewallServiceEnabled;
	private short tcpFlowTableId;
	private int tcpFlowHardTimeout;
	private int tcpFlowIdleTimeout;
	private int tcpFlowPriority;
	
	private AtomicLong flowIdInc = new AtomicLong();
    private AtomicLong flowCookieInc = new AtomicLong(0x2b00000000000000L);
	
	
	public InitialFlowWriter(DataBroker dataBroker, SalFlowService salFlowService, StatefulFirewallConfig firewallConfig) {
		this.dataBroker = dataBroker;
		this.salFlowService = salFlowService;
		this.firewallConfig = firewallConfig;
	
	}
	public void init() {
		this.firewallServiceEnabled = firewallConfig.isStatefulFirewallServiceEnabled();
		this.tcpFlowHardTimeout = firewallConfig.getTcpFlowHardTimeout();
		this.tcpFlowIdleTimeout = firewallConfig.getTcpFlowIdleTimeout();
		this.tcpFlowPriority = firewallConfig.getTcpFlowPriority();
		if(firewallServiceEnabled) {
			registerAsSwitchChangeListener();
			LOG.info("TCP initial flow writer was initialized");
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
				addInitialFlow(node);
			}
		}
		
		public void addInitialFlow(String node) {
			
			writeFlowToSwitch(node, creatTcpToControllerFlow());
			LOG.info("Added tcp flow to CONTROLLER for node {}", node);
			
		}
		
		private Flow creatTcpToControllerFlow() {
			FlowBuilder flowBuilder = new FlowBuilder();
			flowBuilder.setTableId(tcpFlowTableId)//
			.setFlowName("tcptocntrl") // 
			.setId(new FlowId(Long.toString(flowBuilder.hashCode())));// use its own hash code for id.
			
			//set two match fields: ethernetMatch:ethernetType="ipv4" , ipMatch:ipProtocol=6, ipProto="ipv4"
			EthernetMatch ethernetMatch = new EthernetMatchBuilder()
					.setEthernetType(new EthernetTypeBuilder()
							.setType(new EtherType(Long.valueOf(KnownEtherType.Ipv4.getIntValue())))
							.build()).build();
			IpMatch ipMatch = new IpMatchBuilder()
					.setIpProtocol((short)6)
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
            .setPriority(tcpFlowPriority) //
            .setBufferId(0xffffffffL) //
            .setHardTimeout(tcpFlowHardTimeout) //
            .setIdleTimeout(tcpFlowIdleTimeout) //
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
		 
		 private void writeFlowToSwitch(String nodeName, Flow flow) {
			 final AddFlowInputBuilder builder = new AddFlowInputBuilder(flow);
			 final InstanceIdentifier<Node> nodeId = InstanceIdentifier.builder(Nodes.class)
						.child(Node.class, new NodeKey(new NodeId(nodeName)))
						.build();
			 final InstanceIdentifier<Table> tableId = nodeId.builder()
						.augmentation(FlowCapableNode.class)
						.child(Table.class, new TableKey(tcpFlowTableId))
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
