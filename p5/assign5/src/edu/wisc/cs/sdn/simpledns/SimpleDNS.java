package edu.wisc.cs.sdn.simpledns;

import edu.wisc.cs.sdn.simpledns.packet.*;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileNotFoundException;
import java.io.IOException;

import java.net.DatagramSocket;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;

import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;

public class SimpleDNS {

	static DatagramSocket socket;
	static String rootServer = null;
	public static Map<String, String> ec2Map;

	public static void main(String[] args) {
		System.out.println("Hello, DNS!");
		String ec2Csv = null;

		// Get arguments
		for(int i = 0; i < args.length; i++) {
			String arg = args[i];
			if (arg.equals("-r"))
			{ rootServer = args[++i]; }
			else if (arg.equals("-e"))
			{ ec2Csv = args[++i]; }
		}
		if (null == rootServer) return;
		if (null == ec2Csv) return;

		loadEc2(ec2Csv);

		while(true){
			try {
				socket = new DatagramSocket(8053);
			} catch (SocketException e) {
				System.out.println("Socket could not bind to the specified local port");
				return;
			}
			DatagramPacket packet = receiveQueries();					// Get query packet
			if(packet == null) continue;
			InetAddress origIp = packet.getAddress();
			int origPort = packet.getPort();
			DatagramPacket packetReceived = handleQueries(packet);		// Handle the packet and get the response packet
			if(packetReceived == null) continue;
			returnResult(packetReceived, origIp, origPort);				// Return the response packet
			socket.close();
		}
	}

	private static boolean loadEc2(String filename) {
		ec2Map = new HashMap<String, String>();

		// Open the file
		BufferedReader reader;
		try {
			FileReader fileReader = new FileReader(filename);
			reader = new BufferedReader(fileReader);
		} catch (FileNotFoundException e) {
			System.err.println(e.toString());
			return false;
		}

		// Read and parse the file
		while (true) {
			String line = null;
			try {
				line = reader.readLine(); 
			} catch (IOException e) {
				System.err.println(e.toString());
				try { reader.close(); } catch (IOException f) {};
				return false;
			}
			
			// Stop if we have reached the end of the file
			if (null == line) break;

			// Parse the file
			String[] lineSplit = line.split(",");
			ec2Map.put(lineSplit[0], lineSplit[1]);
		}
	
		// Close the file
		try { reader.close(); } catch (IOException f) {};
		return true;
	}

	private static DatagramPacket receiveQueries(){
		byte[] buf = new byte[4096];
		DatagramPacket packet = new DatagramPacket(buf, 4096);
		try {socket.receive(packet);} catch(IOException e) {}
		DNS dns = DNS.deserialize(packet.getData(), packet.getLength());
		if (dns.getOpcode() != DNS.OPCODE_STANDARD_QUERY) return null;
		List<DNSQuestion> questions = dns.getQuestions();
		short qType = dns.getQuestions().get(0).getType();
		if(qType != DNS.TYPE_A && qType != DNS.TYPE_AAAA && qType != DNS.TYPE_CNAME && qType != DNS.TYPE_NS) return null;
		return packet;
	}

	private static DatagramPacket handleQueries(DatagramPacket queryPacket){
		DNS dns = DNS.deserialize(queryPacket.getData(), queryPacket.getLength());

		// Get ipAddress to send to query packet
		InetAddress ipAddress = null;
		try {
			ipAddress = InetAddress.getByName(rootServer);
		} catch(UnknownHostException e) {
			System.out.println("UnknownHostException");
			return null;
		}

		DatagramPacket packetReceived;		// The response Packet

		if(dns.isRecursionDesired()){
			DNSQuestion dnsQ = dns.getQuestions().get(0);		// Get the origional question
			DNS dnsReceived;									// The respond dns packet for each query

			// Recursively query until get the final answer
			while(true) {
				packetReceived = issueQuery(queryPacket, ipAddress, 53);		// Issue a query and get the respond packet
				dnsReceived = DNS.deserialize(packetReceived.getData(), packetReceived.getLength());
				List<DNSResourceRecord> authorities = dnsReceived.getAuthorities();
				List<DNSResourceRecord> answers = dnsReceived.getAnswers();

				// Remove the answers that do not match the question
				List<DNSResourceRecord> answersToRemove = new ArrayList<DNSResourceRecord>();
				for(DNSResourceRecord a : answers) if(!a.getName().equals(dnsQ.getName())) answersToRemove.add(a);
				for(DNSResourceRecord a : answersToRemove) dnsReceived.removeAnswer(a);

				// Test if the answer is a CNAME, if so, continue issue queries until get A or AAAA response
				if(!answers.isEmpty()) {
					if(dnsQ.getType() == DNS.TYPE_A || dnsQ.getType() == DNS.TYPE_AAAA){
						List<DNSResourceRecord> answersNew = new ArrayList<DNSResourceRecord>();
						for(DNSResourceRecord answer : answers) {
							if(answer.getType() != DNS.TYPE_CNAME) continue;
							// Reset the question for new query packet
							dns.removeQuestion(dnsQ);
							dnsQ.setName(answer.getData().toString());
							dns.addQuestion(dnsQ);
							// Handle the query for the CNAME
							queryPacket.setData(dns.serialize());
							queryPacket.setLength(dns.getLength());
							DatagramPacket packetCnameReceived = handleQueries(queryPacket);
							DNS dnsCnameReceived = DNS.deserialize(packetCnameReceived.getData(), packetCnameReceived.getLength());
							// Add the answers of the CNAME query to origional response packet
							for(DNSResourceRecord answerCnameReceived : dnsCnameReceived.getAnswers()) answersNew.add(answerCnameReceived);
							// Set authorities of origional response packet to the response packet of CNAME
							dnsReceived.setAuthorities(dnsCnameReceived.getAuthorities());
						}
						for(DNSResourceRecord answer : answersNew) dnsReceived.addAnswer(answer);	// Add answers to response packet
					}

					packetReceived.setData(dnsReceived.serialize());
					packetReceived.setLength(dnsReceived.getLength());
					break;		// Break the loop when the satisified packet received
				}

				// Set the target ipAddress to next layer of NS
				if(authorities.isEmpty()) continue;
				try {
					ipAddress = InetAddress.getByName(authorities.get(0).getData().toString());
				} catch(UnknownHostException e) {
					System.out.println("UnknownHostException");
					return null;
				}
			}
		} else {
			packetReceived = issueQuery(queryPacket, ipAddress, 53);
		}
		
		return packetReceived;
	}

	private static DatagramPacket issueQuery(DatagramPacket packet, InetAddress ipAddress, int port) {
		DatagramPacket packetReceived = new DatagramPacket(new byte[4096], 4096);
		packet.setPort(port);
		packet.setAddress(ipAddress);
		try {socket.send(packet);} catch(IOException e) {}
		try {socket.receive(packetReceived);} catch(IOException e) {}
		return packetReceived;
	}
	
	private static void returnResult(DatagramPacket packet, InetAddress ip, int port) {
		// Add TXT records for EC2 servers
		DNS dnsReceived = DNS.deserialize(packet.getData(), packet.getLength());
		if(dnsReceived.getQuestions().get(0).getType() == DNS.TYPE_A) {
			List<DNSResourceRecord> answersNew = new ArrayList<DNSResourceRecord>();
			for(DNSResourceRecord answer : dnsReceived.getAnswers()) {
				if(answer.getType() != DNS.TYPE_A) continue;
				String match = ec2Match(answer.getData().toString());
				if(match != null) {
					DNSRdata txtRecordData = new DNSRdataString(match + "-" + answer.getData().toString());
					DNSResourceRecord txtRecord = new DNSResourceRecord(answer.getName(), DNS.TYPE_TXT, txtRecordData);
					answersNew.add(txtRecord);
				}
			}
			for(DNSResourceRecord answerNew : answersNew) dnsReceived.addAnswer(answerNew);
			packet.setData(dnsReceived.serialize());
			packet.setLength(dnsReceived.getLength());
		}
		
		// Send the packet back
		packet.setAddress(ip);
		packet.setPort(port);
		try {socket.send(packet);} catch(IOException e) {}
	}

	private static String ec2Match(String ipString) {
		// Change String ip to int
        String[] ipSplit = ipString.split("\\.");
        int address = 0;
        for (int i = 0; i < 4; ++i) {
            address |= Integer.valueOf(ipSplit[i]) << ((3-i)*8);
        }

		for(String ec2AddStr : ec2Map.keySet()) {
			String[] ec2AddStrSplit = ec2AddStr.split("/");
        	ipSplit = ec2AddStrSplit[0].split("\\.");
			int ec2Address = 0;
			for (int i = 0; i < 4; ++i) {
				ec2Address |= Integer.valueOf(ipSplit[i]) << ((3-i)*8);
			}
			int mask = -1 << (32 - Integer.parseInt(ec2AddStrSplit[1]));	// Calculate the mask
			if((address & mask) == (ec2Address & mask)) return ec2Map.get(ec2AddStr);
		}
		return null;
	}
}