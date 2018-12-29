package edu.wisc.cs.sdn.vnet.sw;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.MACAddress;
import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import java.util.*;

class TimeoutThread extends Thread {
	Map<MACAddress, Iface> sTable;
	Map<MACAddress, Long> tTable;
	TimeoutThread(Map<MACAddress, Iface> sTable, Map<MACAddress, Long> tTable){
		this.sTable = sTable;
		this.tTable = tTable;
	}
	public void run() {
		Iterator it;
		while(true){
			it = tTable.entrySet().iterator();
			while (it.hasNext()) {
				Map.Entry<MACAddress, Long> entry = (Map.Entry)it.next();
				if (System.currentTimeMillis() - entry.getValue() > 15000){
					System.out.println("Remove: " + entry.getKey().toString());
					it.remove();
					sTable.remove(entry.getKey());
				}
			}
			try {
				Thread.sleep(1000);
			} catch (Exception e) {
				System.out.println(e);
			}
		}
	}
}

/**
 * @author Aaron Gember-Jacobson
 */
public class Switch extends Device
{	
	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	Map<MACAddress, Iface> sTable = new HashMap<MACAddress, Iface>();
	Map<MACAddress, Long> tTable = new HashMap<MACAddress, Long>();
	
	public Switch(String host, DumpFile logfile)
	{
		super(host,logfile);
		TimeoutThread t = new TimeoutThread(sTable, tTable);
		t.start();
	}


	private Iface getIface(Ethernet etherPacket, Iface inIface){
		System.out.println("Add: " + etherPacket.getSourceMAC().toString());
		sTable.put(etherPacket.getSourceMAC(), inIface);
		tTable.put(etherPacket.getSourceMAC(), System.currentTimeMillis());
		
		if(sTable.containsKey(etherPacket.getDestinationMAC())){
			return sTable.get(etherPacket.getDestinationMAC());
		} else {
			return null;
		}
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
		Iface outIface = getIface(etherPacket, inIface);
		if(outIface != null){
			System.out.println("Found! " + outIface.toString());
			sendPacket(etherPacket, outIface);
		} else {
			for(Iface oIface : interfaces.values()){
				if(!oIface.getName().equals(inIface.getName())){
					System.out.println("Not Found! " + oIface.toString());
					sendPacket(etherPacket, oIface);
				}
			}
		}
		/********************************************************************/
	}
}
