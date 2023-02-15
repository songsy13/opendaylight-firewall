/*
 * Copyright (c) 2018 Zhejiang University,Song Shuyu.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
package org.opendaylight.firewall.main;

import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.opendaylight.controller.md.sal.binding.api.NotificationPublishService;
import org.opendaylight.l2switch.packethandler.decoders.utils.BitBufferHelper;
import org.opendaylight.l2switch.packethandler.decoders.utils.BufferException;
import org.opendaylight.l2switch.packethandler.decoders.utils.NetUtils;
import org.opendaylight.yang.gen.v1.urn.opendaylight.packet.basepacket.rev140528.packet.chain.grp.PacketChain;
import org.opendaylight.yang.gen.v1.urn.opendaylight.packet.basepacket.rev140528.packet.chain.grp.PacketChainBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.packet.basepacket.rev140528.packet.chain.grp.packet.chain.Packet;
import org.opendaylight.yang.gen.v1.urn.opendaylight.packet.ipv4.rev140528.Ipv4PacketListener;
import org.opendaylight.yang.gen.v1.urn.opendaylight.packet.ipv4.rev140528.Ipv4PacketReceived;
import org.opendaylight.yang.gen.v1.urn.opendaylight.packet.ipv4.rev140528.KnownIpProtocols;
import org.opendaylight.yang.gen.v1.urn.opendaylight.packet.ipv4.rev140528.ipv4.packet.received.packet.chain.packet.Ipv4Packet;
import org.opendaylight.yang.gen.v1.urn.opendaylight.packet.ipv4.tcp.rev180925.TcpPacketReceived;
import org.opendaylight.yang.gen.v1.urn.opendaylight.packet.ipv4.tcp.rev180925.TcpPacketReceivedBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.packet.ipv4.tcp.rev180925.tcp.packet.received.packet.chain.packet.TcpPacketBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.packet.ipv4.udp.rev180925.UdpPacketReceived;
import org.opendaylight.yang.gen.v1.urn.opendaylight.packet.ipv4.udp.rev180925.UdpPacketReceivedBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.packet.ipv4.udp.rev180925.udp.packet.received.packet.chain.packet.UdpPacketBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Ipv4PacketDispatcher implements Ipv4PacketListener {
	
	private static final Logger LOG = LoggerFactory.getLogger(Ipv4PacketDispatcher.class);
	private NotificationPublishService publishService;
	
	private static final int CPUS = Runtime.getRuntime().availableProcessors();
	private final ExecutorService executor = Executors.newFixedThreadPool(CPUS);
	
	public  Ipv4PacketDispatcher(NotificationPublishService publishService) {
		this.publishService = publishService ;
		
		LOG.info("Start Listening IPv4 Packet, and decode to TCP/UDP packet");
	}
		

	@Override
	public void onIpv4PacketReceived(Ipv4PacketReceived notification) {
		executor.execute(new Runnable(){
			@Override
			public void run() {
//				TcpPacketReceived tcpPacketPublishedNotification = null;
//				UdpPacketReceived udpPacketPublishedNotification = null;
				if(notification != null && canDecode(notification)!= null) {
					//LOG.info("Receive an ipv4 packet");
					//tcpPacketPublishedNotification = decodeToTcp(notification);
					switch (canDecode(notification)) {
					case Tcp:
						try {
							publishService.putNotification(decodeToTcp(notification));
						} catch (InterruptedException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
						break;
					case Udp:
						try {
							publishService.putNotification(decodeToUdp(notification));
						} catch (InterruptedException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
						break;
					default:
						return;
					}
				}
			}
			
		});

	}
	private TcpPacketReceived decodeToTcp(Ipv4PacketReceived ipv4PacketReceived) {
		//construct published tcp packet received notification
		TcpPacketReceivedBuilder tcpNotificationBuilder = new TcpPacketReceivedBuilder();
		
		//find the last packet-chain in list, which is an ipv4 packet-chain
		List<PacketChain> packetChainList = ipv4PacketReceived.getPacketChain();
		Ipv4Packet ipv4Packet = (Ipv4Packet) packetChainList.get(packetChainList.size()-1).getPacket();
		int bitOffset = ipv4Packet.getPayloadOffset()*NetUtils.NumBitsInAByte ;
		
		// save the original packet payload
		byte[] data = ipv4PacketReceived.getPayload();
		
		//construct tcp packet
		TcpPacketBuilder builder = new TcpPacketBuilder();
		try {
			builder.setSrcPort(BitBufferHelper.getInt(BitBufferHelper.getBits(data, bitOffset+0, 16)));
			builder.setDstPort(BitBufferHelper.getInt(BitBufferHelper.getBits(data, bitOffset+16, 16)));
			builder.setSeqId(BitBufferHelper.getInt(BitBufferHelper.getBits(data, bitOffset+32, 32)));
			builder.setAckNum(BitBufferHelper.getInt(BitBufferHelper.getBits(data, bitOffset+64, 32)));
			builder.setHeadLength(BitBufferHelper.getShort(BitBufferHelper.getBits(data, bitOffset+96, 4)));
			builder.setReserved(BitBufferHelper.getShort(BitBufferHelper.getBits(data, bitOffset+100, 6)));
			builder.setUrgFlag((BitBufferHelper.getBits(data, bitOffset+106, 1)[0] & 0xff) == 1);
			builder.setAckFlag((BitBufferHelper.getBits(data, bitOffset+107, 1)[0] & 0xff) == 1);
			builder.setPshFlag((BitBufferHelper.getBits(data, bitOffset+108, 1)[0] & 0xff) == 1);
			builder.setRstFlag((BitBufferHelper.getBits(data, bitOffset+109, 1)[0] & 0xff) == 1);
			builder.setSynFlag((BitBufferHelper.getBits(data, bitOffset+110, 1)[0] & 0xff) == 1);
			builder.setFinFlag((BitBufferHelper.getBits(data, bitOffset+111, 1)[0] & 0xff) == 1);
			builder.setReceiveWin(BitBufferHelper.getInt(BitBufferHelper.getBits(data, bitOffset+112, 16)));
			builder.setChecksum(BitBufferHelper.getInt(BitBufferHelper.getBits(data, bitOffset+128, 16)));
			builder.setUrgentPointer(BitBufferHelper.getInt(BitBufferHelper.getBits(data, bitOffset+144, 16)));
			
			//Decode the optional "tcp-options" param  
			//options size = (head length - 160/32 )*32  head length 以32bit的字为单位
			int optionSize = (builder.getHeadLength() - 5)*32;
			if(optionSize > 0) {
				builder.setTcpOptions(BitBufferHelper.getBits(data, bitOffset+160, optionSize));
			}
			
			//Decode the TCP Payload
			int payloadStartInBits = bitOffset + 160 + optionSize ;
			int payloadEndInBits = data.length * NetUtils.NumBitsInAByte - 4 * NetUtils.NumBitsInAByte ;
			int start = payloadStartInBits / NetUtils.NumBitsInAByte ;
			int end = payloadEndInBits / NetUtils.NumBitsInAByte ;
			builder.setPayloadOffset(start);
			builder.setPayloadLength(end - start);
		}catch(BufferException e) {
			LOG.debug("Exception while decoding TCP packet", e.getMessage());
		}
		
		//build tcp packet-chain,  PacketChain: field:Packet (all kinds of packet class are sons of Packet )
		//add it to list<PacketChain>:rawPacketChain,ethernetPacketChain,ipv4PacketChain,tcpPacketChain
		packetChainList.add(new PacketChainBuilder().setPacket(builder.build()).build());
		//build tcp notification: list<packetChain> , original payload
		tcpNotificationBuilder.setPacketChain(packetChainList);
		tcpNotificationBuilder.setPayload(ipv4PacketReceived.getPayload());
		
		return tcpNotificationBuilder.build();
	}
	private UdpPacketReceived decodeToUdp(Ipv4PacketReceived ipv4PacketReceived) {
		UdpPacketReceivedBuilder udpReceivedBuilder = new UdpPacketReceivedBuilder();
		
		List<PacketChain> packetChainList = ipv4PacketReceived.getPacketChain();
		Ipv4Packet ipv4Packet = (Ipv4Packet) packetChainList.get(packetChainList.size() - 1).getPacket();
		int bitOffset = ipv4Packet.getPayloadOffset() * NetUtils.NumBitsInAByte;
        byte[] data = ipv4PacketReceived.getPayload();
        
        UdpPacketBuilder builder = new UdpPacketBuilder();
        try {
        	builder.setSrcPort(BitBufferHelper.getInt(BitBufferHelper.getBits(data, bitOffset+0, 16)));
        	builder.setDstPort(BitBufferHelper.getInt(BitBufferHelper.getBits(data, bitOffset+16, 16)));
        	builder.setHeadLength(BitBufferHelper.getInt(BitBufferHelper.getBits(data, bitOffset+32, 16)));
        	builder.setChecksum(BitBufferHelper.getInt(BitBufferHelper.getBits(data, bitOffset+48, 16)));
        	
        	int payloadStartInBits = bitOffset + 64;
        	int payloadEndInBits = data.length*NetUtils.NumBitsInAByte - 4 * NetUtils.NumBitsInAByte ;
        	int start = payloadStartInBits / NetUtils.NumBitsInAByte;
        	int end = payloadEndInBits / NetUtils.NumBitsInAByte;
        	builder.setPayloadOffset(start);
        	builder.setPayloadLength(end-start);
        }catch(BufferException e) {
			LOG.debug("Exception while decoding UDP packet", e.getMessage());
		}
        
        packetChainList.add(new PacketChainBuilder().setPacket(builder.build()).build());
        udpReceivedBuilder.setPacketChain(packetChainList);
        udpReceivedBuilder.setPayload(ipv4PacketReceived.getPayload());
        
        return udpReceivedBuilder.build();
	}

	
	
	private KnownIpProtocols canDecode(Ipv4PacketReceived ipv4PacketReceived) {
		if (ipv4PacketReceived == null || ipv4PacketReceived.getPacketChain() == null)
            return null;
      // Only decode the latest packet in the chain
      Ipv4Packet ipv4Packet = null;
      if (!ipv4PacketReceived.getPacketChain().isEmpty()) {
          Packet packet = ipv4PacketReceived.getPacketChain().get(ipv4PacketReceived.getPacketChain().size() - 1).getPacket();
          if (packet instanceof Ipv4Packet) {
              ipv4Packet = (Ipv4Packet) packet;
          }
      }
      if(ipv4Packet == null ) {
    	  return null;
      }
      if( !(KnownIpProtocols.Tcp.equals(ipv4Packet.getProtocol()) || 
    		  KnownIpProtocols.Icmp.equals(ipv4Packet.getProtocol()) ||
    				  KnownIpProtocols.Udp.equals(ipv4Packet.getProtocol())) ){
    	  return null;
      }
      return ipv4Packet.getProtocol();
      

		
	}

}
