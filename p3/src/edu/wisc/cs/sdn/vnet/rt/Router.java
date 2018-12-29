package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.*;

import java.nio.ByteBuffer;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Timer;
import java.util.TimerTask;
/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{	
	public byte[] BROADCASE_MAC_ADDRESS = new byte[]{(byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF};
	public int MULTICAST_IP_ADDRESS = IPv4.toIPv4Address("224.0.0.9");
	/** Routing table for the router */
	public RouteTable routeTable;
	
	/** ARP cache for the router */
	public ArpCache arpCache;
	
	public Map<Integer, List<Ethernet>> etherPacketQueue;
	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile)
	{
		super(host,logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
		this.etherPacketQueue = new ConcurrentHashMap<Integer, List<Ethernet>>();
	}
	
	/**
	 * @return routing table for the router
	 */
	public RouteTable getRouteTable()
	{ return this.routeTable; }
	
	/**
	 * Load a new routing table from a file.
	 * @param routeTableFile the name of the file containing the routing table
	 */
	public void loadRouteTable(String routeTableFile)
	{
		if (!routeTable.load(routeTableFile, this))
		{
			System.err.println("Error setting up routing table from file "
					+ routeTableFile);
			System.exit(1);
		}
		
		System.out.println("Loaded static route table");
		System.out.println("-------------------------------------------------");
		System.out.print(this.routeTable.toString());
		System.out.println("-------------------------------------------------");
	}

	public void startRip(){
		for (Iface i : this.interfaces.values()) {
			int dstIp = i.getIpAddress() & i.getSubnetMask();
			int gwIp = 0;
			int maskIp = i.getSubnetMask();
			Iface iface = i;
			this.routeTable.insert(dstIp, gwIp, maskIp, iface, 1, -1);
			sendRipPacket(i, RIPv2.COMMAND_REQUEST, MULTICAST_IP_ADDRESS, BROADCASE_MAC_ADDRESS);
        }
		Timer timer = new Timer();
		SendRipResponseTask task = new SendRipResponseTask(this);
		timer.schedule(task, 10000, 10000);
		Timer timer2 = new Timer();
		RipTimeoutTask task2 = new RipTimeoutTask(this);
		timer2.schedule(task2, 1000, 1000);
		
		System.out.println("Built dynamic route table");
		System.out.println("-------------------------------------------------");
		System.out.print(this.routeTable.toString());
		System.out.println("-------------------------------------------------");
	}
	
	/**
	 * Load a new ARP cache from a file.
	 * @param arpCacheFile the name of the file containing the ARP cache
	 */
	public void loadArpCache(String arpCacheFile)
	{
		if (!arpCache.load(arpCacheFile))
		{
			System.err.println("Error setting up ARP cache from file "
					+ arpCacheFile);
			System.exit(1);
		}
		
		System.out.println("Loaded static ARP cache");
		System.out.println("----------------------------------");
		System.out.print(this.arpCache.toString());
		System.out.println("----------------------------------");
	}

	public void sendICMP(Ethernet etherPacket, Iface inIface, byte icmpType, byte icmpCode, boolean isEcho){
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
		
		Ethernet ether = new Ethernet();
		IPv4 ip = new IPv4();
		ICMP icmp = new ICMP();
		Data data = new Data();
		ether.setPayload(ip);
		ip.setPayload(icmp);
		icmp.setPayload(data);

		ether.setEtherType(Ethernet.TYPE_IPv4);
		ether.setSourceMACAddress(inIface.getMacAddress().toBytes());
		RouteEntry re = this.routeTable.lookup(ipPacket.getSourceAddress());
		int nextHop = re.getGatewayAddress();
		if (0 == nextHop)
		{ nextHop = ipPacket.getSourceAddress(); }
		ArpEntry ae = this.arpCache.lookup(nextHop);
		if(ae == null){
			ether.setDestinationMACAddress(BROADCASE_MAC_ADDRESS);
		} else {
			ether.setDestinationMACAddress(ae.getMac().toBytes());
		}

		ip.setTtl((byte)64);
		ip.setProtocol(IPv4.PROTOCOL_ICMP);
		if(isEcho){
			ip.setSourceAddress(ipPacket.getDestinationAddress());
		} else {
			ip.setSourceAddress(inIface.getIpAddress());
		}
		ip.setDestinationAddress(ipPacket.getSourceAddress());

		icmp.setIcmpType(icmpType);
		icmp.setIcmpCode(icmpCode);

		if(isEcho){
			byte[] icmpPayload = ((ICMP)(ipPacket.getPayload())).getPayload().serialize();
			byte[] dataArray = new byte[icmpPayload.length];
			System.arraycopy(icmpPayload, 0, dataArray, 0, icmpPayload.length);
			data.setData(dataArray);
		} else {
			byte[] padding = new byte[4];
			byte[] ipHeader = ipPacket.serialize();
			byte[] ipPayload = ipPacket.getPayload().serialize();
			byte[] dataArray = new byte[4 + ipHeader.length + 8];
			System.arraycopy(padding, 0, dataArray, 0, 4);
			System.arraycopy(ipHeader, 0, dataArray, 4, ipHeader.length);
			System.arraycopy(ipPayload, 0, dataArray, 4 + ipHeader.length, 8);
			data.setData(dataArray);
		}

		IPv4 new_ip = (IPv4)(ether.getPayload());
		ICMP new_icmp = (ICMP)(new_ip.getPayload());
		Data new_data = (Data)(new_icmp.getPayload());
		this.sendPacket(ether, inIface);
	}

	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface)
	{
		System.out.println("*** -> Received packet: " +
                etherPacket.toString().replace("\n", "\n\t"));
		
		/********************************************************************/
		/* TODO: Handle packets                                             */
		
		switch(etherPacket.getEtherType())
		{
		case Ethernet.TYPE_IPv4:
			this.handleIpPacket(etherPacket, inIface);
			break;
		case Ethernet.TYPE_ARP:
			this.handleArpPacket(etherPacket, inIface);
			break;
		// Ignore all other packet types, for now
		}
		
		/********************************************************************/
	}
	
	public void handleArpPacket(Ethernet etherPacket, Iface inIface){
		// Make sure it's an ARP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_ARP) {
			return;
		}

		// Get ARP header
		ARP arpPacket = (ARP)etherPacket.getPayload();
        System.out.println("handleArpPacket");

		// Verify if the ARP Packet is ARP request
		if(arpPacket.getOpCode() == ARP.OP_REQUEST) {
			// Verify if the target IP address matches interface IP address
			int targetIp = ByteBuffer.wrap(arpPacket.getTargetProtocolAddress()).getInt();
			if(targetIp != inIface.getIpAddress()){
				return;
			}
			System.out.println("handleArpPacket:ARP.OP_REQUEST");
			sendArpReply(etherPacket, inIface);
		} else if (arpPacket.getOpCode() == ARP.OP_REPLY) {

			System.out.println("handleArpPacket:ARP.OP_REPLY");
			// add an entry to the ARP cache (populated from the sender hardware address and sender protocol address fields).
			MACAddress macAddress = MACAddress.valueOf(arpPacket.getSenderHardwareAddress());
			int ipAddress = ByteBuffer.wrap(arpPacket.getSenderProtocolAddress()).getInt();
			this.arpCache.insert(macAddress, ipAddress);
			// dequeue any waiting packets,
			System.out.println("handleArpPacket:ARP.OP_REPLY:Start Dequeue");
			if(etherPacketQueue.get(ipAddress) != null){
				System.out.println("handleArpPacket:ARP.OP_REPLY:Start Dequeue:Found Packet");
				int i = 0;
				while(!etherPacketQueue.get(ipAddress).isEmpty()){
					
					System.out.println("handleArpPacket:ARP.OP_REPLY:Start Dequeue:Found Packet:Dequeue Packet: " + i);
					Ethernet packet = etherPacketQueue.get(ipAddress).remove(0);
					// fill in the correct destination MAC address (from the sender hardware address field on the ARP reply)
					packet.setDestinationMACAddress(macAddress.toBytes());
					// send those packets out the interface on which the ARP reply arrived.
					this.sendPacket(packet, inIface);
					i++;
				}
				System.out.println("handleArpPacket:ARP.OP_REPLY:Start Dequeue:Found Packet:Finished Dequeue");
				etherPacketQueue.remove(ipAddress);
			} else {
				System.out.println("handleArpPacket:ARP.OP_REPLY:Start Dequeue:Not Found Packet");
			}
		} else {
			return;
		}
	}

	public void sendRipPacket(Iface iface, byte command, int destIpAddress, byte[] destMacAddress){
		System.out.println("sendRip " + command);

		Ethernet ether = new Ethernet();
		IPv4 ip = new IPv4();
		UDP udp = new UDP();
		RIPv2 ripv2 = new RIPv2();

		ether.setPayload(ip);
		ip.setPayload(udp);
		udp.setPayload(ripv2);

		ether.setEtherType(Ethernet.TYPE_IPv4);
		ether.setSourceMACAddress(iface.getMacAddress().toBytes());
		ether.setDestinationMACAddress(destMacAddress);

		ip.setSourceAddress(iface.getIpAddress());
		ip.setDestinationAddress(destIpAddress);
		ip.setTtl((byte)64);
		ip.setProtocol(IPv4.PROTOCOL_UDP);

		udp.setSourcePort(UDP.RIP_PORT);
		udp.setDestinationPort(UDP.RIP_PORT);

		ripv2.setCommand(command);
		if(command == RIPv2.COMMAND_RESPONSE){
			for (RouteEntry re : this.routeTable.getEntries()){
				RIPv2Entry ripv2Entry = new RIPv2Entry(re.getDestinationAddress(), re.getMaskAddress(), re.getDistance());
				ripv2Entry.setNextHopAddress(iface.getIpAddress());
				ripv2.addEntry(ripv2Entry);
			}
		}

		this.sendPacket(ether, iface);
	}

	private void sendArpReply(Ethernet etherPacket, Iface inIface){
		// Make sure it's an ARP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_ARP) {
			return;
		}
		System.out.println("sendArpReply");
		
		// Get ARP header
		ARP arpPacket = (ARP)etherPacket.getPayload();

		// Construct ARP reply packet
		Ethernet ether = new Ethernet();
		ARP arp = new ARP();
		ether.setPayload(arp);

		// Populate Ethernet header
		ether.setEtherType(Ethernet.TYPE_ARP);
		ether.setSourceMACAddress(inIface.getMacAddress().toBytes());
		ether.setDestinationMACAddress(etherPacket.getSourceMACAddress());

		// Populate ARP header
		arp.setHardwareType(ARP.HW_TYPE_ETHERNET);
		arp.setProtocolType(ARP.PROTO_TYPE_IP);
		arp.setHardwareAddressLength((byte)Ethernet.DATALAYER_ADDRESS_LENGTH);
		arp.setProtocolAddressLength((byte)4);
		arp.setOpCode(ARP.OP_REPLY);
		arp.setSenderHardwareAddress(inIface.getMacAddress().toBytes());
		arp.setSenderProtocolAddress(inIface.getIpAddress());
		arp.setTargetHardwareAddress(arpPacket.getSenderHardwareAddress());
		arp.setTargetProtocolAddress(arpPacket.getSenderProtocolAddress());

		// Send the ARP reply packet back
		this.sendPacket(ether, inIface);
		System.out.println("sendArpReply:Done");
	}

	public void sendArpRequest(Ethernet etherPacket, Iface inIface, byte[] targetProtocolAddress){
		System.out.println("sendArpRequest");
		// Construct ARP request packet
		Ethernet ether = new Ethernet();
		ARP arp = new ARP();
		ether.setPayload(arp);

		// Populate Ethernet header
		ether.setEtherType(Ethernet.TYPE_ARP);
		ether.setSourceMACAddress(inIface.getMacAddress().toBytes());
		ether.setDestinationMACAddress(BROADCASE_MAC_ADDRESS);

		// Populate ARP header
		arp.setHardwareType(ARP.HW_TYPE_ETHERNET);
		arp.setProtocolType(ARP.PROTO_TYPE_IP);
		arp.setHardwareAddressLength((byte)Ethernet.DATALAYER_ADDRESS_LENGTH);
		arp.setProtocolAddressLength((byte)4);
		arp.setOpCode(ARP.OP_REQUEST);
		arp.setSenderHardwareAddress(inIface.getMacAddress().toBytes());
		arp.setSenderProtocolAddress(IPv4.toIPv4AddressBytes(inIface.getIpAddress()));
		arp.setTargetHardwareAddress(new byte[]{0, 0, 0, 0, 0, 0});
		arp.setTargetProtocolAddress(targetProtocolAddress);

		// Send the ARP request packet back
		this.sendPacket(ether, inIface);
		System.out.println("sendArpRequest:Done");
	}

	private void handleIpPacket(Ethernet etherPacket, Iface inIface)
	{
		// Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
		{ return; }
		
		// Get IP header
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
        System.out.println("handleIpPacket");

        // Verify checksum
        short origCksum = ipPacket.getChecksum();
        ipPacket.resetChecksum();
        byte[] serialized = ipPacket.serialize();
        ipPacket.deserialize(serialized, 0, serialized.length);
        short calcCksum = ipPacket.getChecksum();
        if (origCksum != calcCksum)
        { return; }
        
        // Check TTL
        ipPacket.setTtl((byte)(ipPacket.getTtl()-1));
        if (0 == ipPacket.getTtl())
        {
			sendICMP(etherPacket, inIface, (byte)11, (byte)0, false);
			return; 
		}
        
        // Reset checksum now that TTL is decremented
        ipPacket.resetChecksum();
        
        // Check if packet is destined for one of router's interfaces
        for (Iface iface : this.interfaces.values())
        {
        	if (ipPacket.getDestinationAddress() == iface.getIpAddress())
        	{
				if(ipPacket.getProtocol() == IPv4.PROTOCOL_UDP || ipPacket.getProtocol() == IPv4.PROTOCOL_TCP){
					if(ipPacket.getProtocol() == IPv4.PROTOCOL_UDP){
						UDP udp = (UDP)ipPacket.getPayload();
						if(udp.getDestinationPort() == UDP.RIP_PORT && udp.getSourcePort() == UDP.RIP_PORT){
							handleRipPacket(etherPacket, inIface);
						}
					}
					sendICMP(etherPacket, inIface, (byte)3, (byte)3, false);
				}
				if(ipPacket.getProtocol() == IPv4.PROTOCOL_ICMP){
					ICMP icmp = (ICMP)(ipPacket.getPayload());
					if(icmp.getIcmpType() == 8){
						sendICMP(etherPacket, inIface, (byte)0, (byte)0, true);
					}
				}
				return;
			}
        }
		
		if(ipPacket.getDestinationAddress() == MULTICAST_IP_ADDRESS && ipPacket.getProtocol() == IPv4.PROTOCOL_UDP){
			System.out.println("handleIpPacket:RIP Packet Received!");
			UDP udp = (UDP)ipPacket.getPayload();
			if(udp.getDestinationPort() == UDP.RIP_PORT && udp.getSourcePort() == UDP.RIP_PORT){
				handleRipPacket(etherPacket, inIface);
			}
			return;
		}

        // Do route lookup and forward
        this.forwardIpPacket(etherPacket, inIface);
	}

	private void handleRipPacket(Ethernet etherPacket, Iface inIface){
		System.out.println("handleRipPacket:RIP Packet handled!");
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
		UDP udp = (UDP)ipPacket.getPayload();
		RIPv2 ripv2 = (RIPv2)udp.getPayload();
		if(ripv2.getCommand() == RIPv2.COMMAND_REQUEST) {
			System.out.println("handleIpPacket:RIP COMMAND_REQUEST Packet Received! Send RIP Response!");
			sendRipPacket(inIface, RIPv2.COMMAND_RESPONSE, ipPacket.getSourceAddress(), etherPacket.getSourceMACAddress());
		} else if (ripv2.getCommand() == RIPv2.COMMAND_RESPONSE) {
			boolean ifUpdate = false;
			System.out.println("handleIpPacket:RIP COMMAND_RESPONSE Packet Received! Update Route Table!");
			for(RIPv2Entry ripv2Entry : ripv2.getEntries()){
				RouteEntry routeEntry = this.routeTable.lookup(ripv2Entry.getAddress());
				if(routeEntry == null){
					int dstIp = ripv2Entry.getAddress();
					int gwIp = ripv2Entry.getNextHopAddress();
					int maskIp = ripv2Entry.getSubnetMask();
					Iface iface = inIface;
					this.routeTable.insert(dstIp, gwIp, maskIp, iface, ripv2Entry.getMetric() + 1, System.currentTimeMillis());
					ifUpdate = true;
				} else {
					if(routeEntry.getDistance() > ripv2Entry.getMetric() + 1){
						int dstIp = ripv2Entry.getAddress();
						int gwIp = ripv2Entry.getNextHopAddress();
						int maskIp = ripv2Entry.getSubnetMask();
						Iface iface = inIface;
						this.routeTable.update(dstIp, maskIp, gwIp, iface, ripv2Entry.getMetric() + 1, System.currentTimeMillis());
						ifUpdate = true;
					}
					if(routeEntry.getDistance() == ripv2Entry.getMetric() + 1){
						int dstIp = ripv2Entry.getAddress();
						int gwIp = ripv2Entry.getNextHopAddress();
						int maskIp = ripv2Entry.getSubnetMask();
						Iface iface = inIface;
						this.routeTable.update(dstIp, maskIp, gwIp, iface, ripv2Entry.getMetric() + 1, System.currentTimeMillis());
						ifUpdate = false;
					}
				}
			}
			if(ifUpdate){
				sendRipPacket(inIface, RIPv2.COMMAND_RESPONSE, MULTICAST_IP_ADDRESS, BROADCASE_MAC_ADDRESS);
				System.out.println("handleIpPacket:RIP Packet Received! Route Table Updated!");
				System.out.println("-------------------------------------------------");
				System.out.print(this.routeTable.toString());
				System.out.println("-------------------------------------------------");
			}
		}
	}

    private void forwardIpPacket(Ethernet etherPacket, Iface inIface)
    {
        // Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
		{ return; }
        System.out.println("forwardIpPacket");
		
		// Get IP header
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
        int dstAddr = ipPacket.getDestinationAddress();

        // Find matching route table entry 
        RouteEntry bestMatch = this.routeTable.lookup(dstAddr);

        // If no entry matched, do nothing
        if (null == bestMatch)
        {
			sendICMP(etherPacket, inIface, (byte)3, (byte)0, false);
			return;
		}

        // Make sure we don't sent a packet back out the interface it came in
        Iface outIface = bestMatch.getInterface();
        if (outIface == inIface)
        { return; }

        // Set source MAC address in Ethernet header
        etherPacket.setSourceMACAddress(outIface.getMacAddress().toBytes());

        // If no gateway, then nextHop is IP destination
        int nextHop = bestMatch.getGatewayAddress();
        if (0 == nextHop)
        { nextHop = dstAddr; }

        // Set destination MAC address in Ethernet header
        ArpEntry arpEntry = this.arpCache.lookup(nextHop);
        if (null == arpEntry)
        {
			//sendICMP(etherPacket, inIface, (byte)3, (byte)1, false);
			
			// enqueue the packet
			
			System.out.println("forwardIpPacket:arpEntry Not Found! " + IPv4.fromIPv4Address(nextHop));
			if(etherPacketQueue.get(nextHop) == null){
				System.out.println("forwardIpPacket:arpEntry Not Found! New Entry in MAP");
				etherPacketQueue.put(nextHop, new ArrayList<Ethernet> ());
			}
			System.out.println("forwardIpPacket:arpEntry Not Found! Add To Queue");
			etherPacketQueue.get(nextHop).add(etherPacket);
			System.out.println("forwardIpPacket:arpEntry Not Found! Queue " + IPv4.fromIPv4Address(nextHop) + " Size: " + etherPacketQueue.get(nextHop).size());
			
			//this.sendArpRequest(etherPacket, outIface, IPv4.toIPv4AddressBytes(nextHop));
			// generate an ARP request
			// timer task to send arp request for every second until received arp reply or send 3 times.

			
			System.out.println("forwardIpPacket:arpEntry Not Found! Set Up Timer");
			Timer timer = new Timer();
			SendArpRequestTask task = new SendArpRequestTask(this, 3, timer, etherPacket, inIface, outIface, nextHop);
			timer.schedule(task, 0, 1000);

			System.out.println("forwardIpPacket:arpEntry Not Found! Done");
			return;
		}
        etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());
        
        this.sendPacket(etherPacket, outIface);
    }
}

class SendArpRequestTask extends TimerTask {
	Router router;
	private int count;
	private Timer timer;
	private Ethernet etherPacket;
	private Iface inIface;
	private Iface outIface;
	private int targetProtocolAddress;

	public SendArpRequestTask(Router router, int count, Timer timer, Ethernet etherPacket, Iface inIface, Iface outIface, int targetProtocolAddress) {
		this.router = router;
		this.count = count;
		this.timer = timer;
		this.etherPacket = etherPacket;
		this.inIface = inIface;
		this.outIface = outIface;
		this.targetProtocolAddress = targetProtocolAddress;
	}

	public void run() {
		if(router.arpCache.lookup(targetProtocolAddress) != null){
			System.out.println("ARP REPLY FOUND! STOP SENDING ARP REQUEST");
			timer.cancel();
			return;
		}
		if(count == 0){
			System.out.println("ARP REQUEST SENT 3 TIMES! STOP SENDING ARP REQUEST");
			System.out.println("ARP REQUEST SENT 3 TIMES! SENDING ICMP");
			if(router.etherPacketQueue.get(targetProtocolAddress) != null){
				while(!router.etherPacketQueue.get(targetProtocolAddress).isEmpty()){
					Ethernet packet = router.etherPacketQueue.get(targetProtocolAddress).remove(0);
					router.sendICMP(packet, inIface, (byte)3, (byte)1, false);
				}
				router.etherPacketQueue.remove(targetProtocolAddress);
			}
			timer.cancel();
			return;
		}
		System.out.println("Send ARP Request: " + targetProtocolAddress + "time: " + count);
		router.sendArpRequest(etherPacket, outIface, IPv4.toIPv4AddressBytes(targetProtocolAddress));
		count--;
	}
}

class SendRipResponseTask extends TimerTask {
	Router router;

	public SendRipResponseTask(Router router) {
		this.router = router;
	}

	public void run() {
		for (Iface i : this.router.getInterfaces().values()) {
			router.sendRipPacket(i, RIPv2.COMMAND_RESPONSE, router.MULTICAST_IP_ADDRESS, router.BROADCASE_MAC_ADDRESS);
        }
	}
}

class RipTimeoutTask extends TimerTask {
	Router router;

	public RipTimeoutTask(Router router) {
		this.router = router;
	}

	public void run() {
		for (RouteEntry re : this.router.routeTable.getEntries()){
			if(re.getUpdateTime() != -1 && System.currentTimeMillis() - re.getUpdateTime() > 30000){
				System.out.println("Time Out Route Entry!");
				this.router.routeTable.remove(re.getDestinationAddress(), re.getMaskAddress());
			}
		}
	}
}