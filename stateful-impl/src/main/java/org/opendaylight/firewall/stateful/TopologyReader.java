/*
 * Copyright (c) 2018 Zhejiang University,Song Shuyu.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

package org.opendaylight.firewall.stateful;

import java.util.List;
import java.util.concurrent.ExecutionException;

import org.opendaylight.controller.md.sal.binding.api.DataBroker;
import org.opendaylight.controller.md.sal.binding.api.ReadOnlyTransaction;
import org.opendaylight.controller.md.sal.binding.api.ReadTransaction;
import org.opendaylight.controller.md.sal.common.api.data.LogicalDatastoreType;
import org.opendaylight.controller.md.sal.common.api.data.ReadFailedException;
import org.opendaylight.yang.gen.v1.urn.ietf.params.xml.ns.yang.ietf.yang.types.rev130715.MacAddress;
import org.opendaylight.yang.gen.v1.urn.opendaylight.address.tracker.rev140617.address.node.connector.Addresses;
import org.opendaylight.yang.gen.v1.urn.opendaylight.host.tracker.rev140624.HostNode;
import org.opendaylight.yang.gen.v1.urn.opendaylight.host.tracker.rev140624.host.AttachmentPoints;
import org.opendaylight.yang.gen.v1.urn.opendaylight.inventory.rev130819.NodeConnectorId;
import org.opendaylight.yang.gen.v1.urn.opendaylight.inventory.rev130819.NodeConnectorRef;
import org.opendaylight.yang.gen.v1.urn.opendaylight.inventory.rev130819.NodeId;
import org.opendaylight.yang.gen.v1.urn.opendaylight.inventory.rev130819.Nodes;
import org.opendaylight.yang.gen.v1.urn.opendaylight.inventory.rev130819.node.NodeConnector;
import org.opendaylight.yang.gen.v1.urn.opendaylight.inventory.rev130819.node.NodeConnectorKey;
import org.opendaylight.yang.gen.v1.urn.tbd.params.xml.ns.yang.network.topology.rev131021.NetworkTopology;
import org.opendaylight.yang.gen.v1.urn.tbd.params.xml.ns.yang.network.topology.rev131021.TopologyId;
import org.opendaylight.yang.gen.v1.urn.tbd.params.xml.ns.yang.network.topology.rev131021.TpId;
import org.opendaylight.yang.gen.v1.urn.tbd.params.xml.ns.yang.network.topology.rev131021.network.topology.Topology;
import org.opendaylight.yang.gen.v1.urn.tbd.params.xml.ns.yang.network.topology.rev131021.network.topology.TopologyKey;
import org.opendaylight.yang.gen.v1.urn.tbd.params.xml.ns.yang.network.topology.rev131021.network.topology.topology.Node;
import org.opendaylight.yang.gen.v1.urn.tbd.params.xml.ns.yang.network.topology.rev131021.network.topology.topology.NodeKey;
import org.opendaylight.yangtools.yang.binding.InstanceIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Optional;
import com.google.common.util.concurrent.CheckedFuture;

public class TopologyReader {
	
	private static final Logger LOG = LoggerFactory.getLogger(TopologyReader.class);
	private static final String TopoName = "flow:1";
	private DataBroker dataBroker ;
	
	public TopologyReader(DataBroker dataBroker) {
		this.dataBroker = dataBroker;
	}
	/*
	 * Get the NodeConnector with the specified MacAddress in the knonw topology
     * @param dest MacAddress of received tcp packet 
	 */
	public NodeConnectorRef getDstNodeConnectorRef(MacAddress dstMac) {
		if(dstMac == null) {
			return null;
		}
		String mac = dstMac.getValue();
		NodeConnectorRef destNodeConnectorRef = null ;
		// read host-node augumentation specfied by node-id: "HOST:mac"
		HostNode hostNode = readHostNodeByHostMac(mac);
		if(hostNode == null) {
			return null;
		}
		List<Addresses> hostAddress = hostNode.getAddresses();
		MacAddress hostMac = hostAddress.get(0).getMac();
		//Compare the host-node mac address with dstMac to check if we find correct host node;
		// if true, find the tp-id of host-node's attachmentpoint whose pattern is "openflow:1:1".
		// so we could find the dstNodeConnector 
		if(hostMac != null && hostMac.equals(dstMac)) {
			List<AttachmentPoints> aps = hostNode.getAttachmentPoints();
			TpId tpId = aps.get(0).getTpId();
			if(tpId != null) {
				String nodeConnectorName = tpId.getValue();
				String nodeName = nodeConnectorName.split(":")[0]+":"+nodeConnectorName.split(":")[1];
				destNodeConnectorRef = new NodeConnectorRef(InstanceIdentifier.builder(Nodes.class)
						.child(org.opendaylight.yang.gen.v1.urn.opendaylight.inventory.rev130819.nodes.Node.class,
								new org.opendaylight.yang.gen.v1.urn.opendaylight.inventory.rev130819.nodes.NodeKey(
										new NodeId(nodeName)))
						.child(NodeConnector.class, new NodeConnectorKey(new NodeConnectorId(nodeConnectorName)))
						.build());
			}
		}
		return destNodeConnectorRef;
	}
		
//		// read all nodes
//		List<Node> nodes = readNodesFromNetworkTopology();
//		if(nodes == null) {
//			return null;
//		}
//		for(Node node:nodes) {
//			//find host nodes
//			if("HOST".equals(node.getKey().getNodeId().getValue().substring(0, 4).toUpperCase())){
//				HostNode hostNode = readHostNodeFromNode(node);
//				if(hostNode != null) {
//					List<Addresses> hostAddress = hostNode.getAddresses();
//					MacAddress hostMac = hostAddress.get(0).getMac();
//					//find dstMac corresponding dst nodeconnector
//					if(hostMac!= null && dstMac.equals(hostMac)) {
//						List<AttachmentPoints> aps =  hostNode.getAttachmentPoints();
//						TpId tpId = aps.get(0).getTpId();
//						if(tpId!=null) {
//							String NodeConnectorName = tpId.getValue();
//							String NodeName = NodeConnectorName.split(":")[0]+":"+NodeConnectorName.split(":")[1];
//							destNodeConnector = new NodeConnectorRef(InstanceIdentifier.builder(Nodes.class)
//									.child(org.opendaylight.yang.gen.v1.urn.opendaylight.inventory.rev130819.nodes.Node.class,
//											new org.opendaylight.yang.gen.v1.urn.opendaylight.inventory.rev130819.nodes.NodeKey(
//													new NodeId(NodeName)))
//									.child(NodeConnector.class, new NodeConnectorKey(new NodeConnectorId(NodeConnectorName)))
//									.build());
//							break;
//							
//						}
//					}
//				}
//			}
//		}
//		return destNodeConnector;
		
//	}
	
//	grouping host {
//  description "List of addresses and attachment points";
//  uses at:address-node-connector;
//  leaf id {
//      type host-id;
//  }
//  list attachment-points {
//      description "the assumption is that all address can be reached at all attachment points";
//      uses topo:tp-attributes;
//      key tp-id;
//      leaf corresponding-tp {
//          type topo:tp-ref;
//      }
//      leaf active {
//          type boolean;
//      }
//  }
//}
//
//augment "/topo:network-topology/topo:topology/topo:node" {
//  ext:augment-identifier "host-node";
//  uses host;
//}
	
	/*
	 * Read HostNode with specific nodeId whose pattern is HOST:{MacAddress}
	 * @param  construct the NodeId _value whose son host-node will be read;
	 */
	private HostNode readHostNodeByHostMac(String mac) {
		if(mac==null) {
			return null;
		}
		String nodeIdValue = "host:" + mac ;
		InstanceIdentifier<HostNode> hostNodeId = InstanceIdentifier.builder(NetworkTopology.class)//
				.child(Topology.class, new TopologyKey(new TopologyId(TopoName)))//
				.child(Node.class, new NodeKey(
						new org.opendaylight.yang.gen.v1.urn.tbd.params.xml.ns.yang.network.topology.rev131021.NodeId(nodeIdValue)))//
				.augmentation(HostNode.class).build();
		ReadOnlyTransaction tr = dataBroker.newReadOnlyTransaction();
		Optional<HostNode> hostNode = null;
		try {
			CheckedFuture<Optional<HostNode>, ReadFailedException> future = 
					tr.read(LogicalDatastoreType.OPERATIONAL, hostNodeId);
			tr.close();
			hostNode = future.get();
			if(hostNode!=null && !hostNode.isPresent()) {
				LOG.warn("Network-Topology:flow:1:{}: host-node data tree doesn't exist", nodeIdValue);
			}
		}catch(InterruptedException | ExecutionException e) {
			LOG.warn("Reading augmentation:HostNode failed");
		}
		return hostNode.get();
		
		
	}
	
//	private List<Node> readNodesFromNetworkTopology(){
//		InstanceIdentifier<Node> nodesId = InstanceIdentifier.builder(NetworkTopology.class)
//				.child(container)
//		InstanceIdentifier<Topology> topoId = InstanceIdentifier.builder(NetworkTopology.class)
//				.child(Topology.class, new TopologyKey(new TopologyId(TopoName))).build();
//		ReadOnlyTransaction tr = dataBroker.newReadOnlyTransaction();
//		Optional<Topology> topology = null ;
//		try {
//			CheckedFuture<Optional<Topology>, ReadFailedException> future = 
//					tr.read(LogicalDatastoreType.OPERATIONAL, topoId);
//			tr.close();
//			topology = future.get();
//			if(topology != null && !topology.isPresent()) {
//				LOG.warn("Network-Topology:flow:1 topology data tree doesn't exist");
//    			return null;
//			}
//			
//		}catch(InterruptedException e) {
//			LOG.warn("Reading Topology information failed.");
//		} catch (ExecutionException e) {
//			e.printStackTrace();
//		}
//		return topology.get().getNode();
//	}
//	
//	
//	private HostNode readHostNodeFromNode(Node node) {
//		InstanceIdentifier<HostNode> hostNodeId = InstanceIdentifier.builder(NetworkTopology.class)//
//                .child(Topology.class, new TopologyKey(new TopologyId(TopoName)))//
//                .child(Node.class , node.getKey())
//               // .child(Node.class)
//                .augmentation(HostNode.class).build();
//		ReadOnlyTransaction tr = dataBroker.newReadOnlyTransaction();
//		Optional<HostNode> hostNode = null;
//		try {
//			CheckedFuture<Optional<HostNode>, ReadFailedException> future = 
//					tr.read(LogicalDatastoreType.OPERATIONAL, hostNodeId);
//			tr.close();
//			hostNode = future.get();
//			if(hostNode!=null && !hostNode.isPresent()) {
//				LOG.warn("Network-Topology:flow:1:{}: host-node data tree doesn't exist",node);
//			}
//		}catch(InterruptedException | ExecutionException e) {
//			LOG.warn("Reading augmentation:HostNode failed");
//		}
//		return hostNode.get();
//	}

}
