package org.example.PcapAnaysisOnJava;

import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapHandle.TimestampPrecision;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;

public class PcapReader {

	public static void main(String[] args) {
		String pcapFilePath = "test.pcap";
        try {
            PcapHandle handle = Pcaps.openOffline(pcapFilePath, TimestampPrecision.NANO);
            Packet packet;
            while ((packet = handle.getNextPacket()) != null) {
            	EthernetPacket EthernetFrame = packet.get(EthernetPacket.class);
            	System.out.println("Source MAC Address: "+EthernetFrame.getHeader().getSrcAddr());
            	System.out.println("Destination MAC Address: "+EthernetFrame.getHeader().getDstAddr());
                if (packet.contains(IpV4Packet.class)) {
                    IpV4Packet ipPacket = packet.get(IpV4Packet.class);
                    System.out.println(ipPacket.getHeader().getTtl());
                    String srcIp = ipPacket.getHeader().getSrcAddr().getHostAddress();
                    String dstIp = ipPacket.getHeader().getDstAddr().getHostAddress();

                    System.out.println("Source IP: " + srcIp);
                    System.out.println("Destination IP: " + dstIp);

                    if (packet.contains(TcpPacket.class)) {
                        TcpPacket tcpPacket = packet.get(TcpPacket.class);
                        int srcPort = tcpPacket.getHeader().getSrcPort().valueAsInt();
                        int dstPort = tcpPacket.getHeader().getDstPort().valueAsInt();
                        int payloadLength = tcpPacket.getPayload() != null 
                                            ? tcpPacket.getPayload().length() 
                                            : 0;

                       System.out.println("Source Port: " + srcPort);
                       System.out.println("Destination Port: " + dstPort);
                       System.out.println("TCP Payload Length: " + payloadLength);
                    }
                }
                System.out.println("----------------------------");
            }
            handle.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
	}

}
