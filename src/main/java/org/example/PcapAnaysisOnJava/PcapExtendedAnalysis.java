package org.example.PcapAnaysisOnJava;

import org.pcap4j.core.*;
import org.pcap4j.packet.*;

import java.io.*;
import java.util.*;

public class PcapExtendedAnalysis {
	private static final String PCAP_FILE = "test.pcap";
    private static final String OUI_FILE = "mac-vendor.txt";
    private static final Map<Integer, String> OUI_MAP = new HashMap<>();
    
    private static final Map<String, String> PORT_PROTOCOL_MAP = new HashMap<>();
    static {
        // Add known port to protocol mappings
        PORT_PROTOCOL_MAP.put("20_TCP", "FTP Data Transfer [TCP]");
        PORT_PROTOCOL_MAP.put("21_TCP", "FTP Control [TCP]");
        PORT_PROTOCOL_MAP.put("22_TCP", "SSH [TCP]");
        PORT_PROTOCOL_MAP.put("23_TCP", "TELNET [TCP]");
        PORT_PROTOCOL_MAP.put("25_TCP", "SMTP [TCP]");
        PORT_PROTOCOL_MAP.put("53_TCP", "DNS [TCP]");
        PORT_PROTOCOL_MAP.put("53_UDP", "DNS [UDP]");
        PORT_PROTOCOL_MAP.put("67_UDP", "DHCP [UDP]");
        PORT_PROTOCOL_MAP.put("68_UDP", "DHCP [UDP]");
        PORT_PROTOCOL_MAP.put("69_UDP", "TFTP [UDP]");
        PORT_PROTOCOL_MAP.put("80_TCP", "HTTP [TCP]");
        PORT_PROTOCOL_MAP.put("110_TCP", "POP3 [TCP]");
        PORT_PROTOCOL_MAP.put("123_UDP", "NTP [UDP]");
        PORT_PROTOCOL_MAP.put("143_TCP", "IMAP [TCP]");
        PORT_PROTOCOL_MAP.put("161_UDP", "SNMP [UDP]");
        PORT_PROTOCOL_MAP.put("162_UDP", "SNMP Trap [UDP]");
        PORT_PROTOCOL_MAP.put("179_TCP", "BGP [TCP]");
        PORT_PROTOCOL_MAP.put("443_TCP", "HTTPS [TCP]");
        PORT_PROTOCOL_MAP.put("445_TCP", "SMB [TCP]");
        PORT_PROTOCOL_MAP.put("465_TCP", "SMTPS [TCP]");
        PORT_PROTOCOL_MAP.put("502_TCP", "Modbus TCP [TCP]");
        PORT_PROTOCOL_MAP.put("514_UDP", "Syslog [UDP]");
        PORT_PROTOCOL_MAP.put("515_TCP", "LPD [TCP]");
        PORT_PROTOCOL_MAP.put("520_UDP", "RIP [UDP]");
        PORT_PROTOCOL_MAP.put("587_TCP", "SMTP Submission [TCP]");
        PORT_PROTOCOL_MAP.put("623_UDP", "IPMI [UDP]");
        PORT_PROTOCOL_MAP.put("993_TCP", "IMAPS [TCP]");
        PORT_PROTOCOL_MAP.put("995_TCP", "POP3S [TCP]");
        PORT_PROTOCOL_MAP.put("102_TCP", "MMS [TCP]");
        PORT_PROTOCOL_MAP.put("1080_TCP", "SOCKS [TCP]");
        PORT_PROTOCOL_MAP.put("1433_TCP", "MSSQL [TCP]");
        PORT_PROTOCOL_MAP.put("1521_TCP", "Oracle DB [TCP]");
        PORT_PROTOCOL_MAP.put("1723_TCP", "PPTP [TCP]");
        PORT_PROTOCOL_MAP.put("1883_TCP", "MQTT [TCP]");
        PORT_PROTOCOL_MAP.put("2404_TCP", "IEC 60870-5 -104 [TCP]");
        PORT_PROTOCOL_MAP.put("3306_TCP", "MySQL [TCP]");
        PORT_PROTOCOL_MAP.put("3389_TCP", "RDP [TCP]");
        PORT_PROTOCOL_MAP.put("5432_TCP", "PostgreSQL [TCP]");
        PORT_PROTOCOL_MAP.put("5631_TCP", "pcAnywhere [TCP]");
        PORT_PROTOCOL_MAP.put("5632_UDP", "pcAnywhere [UDP]");
        PORT_PROTOCOL_MAP.put("5900_TCP", "VNC [TCP]");
        PORT_PROTOCOL_MAP.put("6379_TCP", "Redis [TCP]");
        PORT_PROTOCOL_MAP.put("8080_TCP", "HTTP Proxy [TCP]");
        PORT_PROTOCOL_MAP.put("8443_TCP", "HTTPS Alt [TCP]");
        PORT_PROTOCOL_MAP.put("8883_TCP", "MQTT over TLS [TCP]");
        PORT_PROTOCOL_MAP.put("44818_TCP", "EthernetIP [TCP]");
        PORT_PROTOCOL_MAP.put("44818_UDP", "EthernetIP [UDP]");
        PORT_PROTOCOL_MAP.put("1911_TCP", "Tridium Niagara Fox [TCP]");
        PORT_PROTOCOL_MAP.put("1911_UDP", "Tridium Niagara Fox [UDP]");
        PORT_PROTOCOL_MAP.put("20000_TCP", "DNP3 [TCP]");
        PORT_PROTOCOL_MAP.put("20000_UDP", "DNP3 [UDP]");
        PORT_PROTOCOL_MAP.put("47808_TCP", "BACnet [TCP]");
        PORT_PROTOCOL_MAP.put("47808_UDP", "BACnet [UDP]");
        PORT_PROTOCOL_MAP.put("18245_TCP", "OPC UA [TCP]");
        PORT_PROTOCOL_MAP.put("18245_UDP", "OPC UA [UDP]");
        PORT_PROTOCOL_MAP.put("4840_TCP", "OPC UA [TCP]");
        PORT_PROTOCOL_MAP.put("4840_UDP", "OPC UA [UDP]");
    }

    public static void main(String[] args) {
        loadOUIIndex();
        analyzePcap(PCAP_FILE);
    }

    private static void loadOUIIndex() {
        try (BufferedReader br = new BufferedReader(new FileReader(OUI_FILE))) {
            String line;
            while ((line = br.readLine()) != null) {
                String[] parts = line.split("\\s+", 2);
                if (parts.length == 2) {
                    int oui = Integer.parseInt(parts[0], 16);
                    OUI_MAP.put(oui, parts[1]);
                }
            }
        } catch (IOException e) {
            System.err.println("Error reading OUI index: " + e.getMessage());
        }
    }

    private static String lookupVendor(String macAddress) {
        String ouiPart = macAddress.replace(":", "").substring(0, 6).toUpperCase();
        int oui = Integer.parseInt(ouiPart, 16);
        return OUI_MAP.getOrDefault(oui, "UNKNOWN_VENDOR");
    }

    private static String detectOS(int ttl) {
        return ttl <= 64 ? "Linux/macOS" : ttl <= 128 ? "Windows" : "Network Device";
    }

    private static void analyzePcap(String pcapFile) {
        try (PcapHandle handle = Pcaps.openOffline(pcapFile)) {
        	Map<String, String[]> ipInfo = new HashMap<>();
            Map<String, Integer> commCounts = new HashMap<>();
            Map<String, String> ipCommunications = new HashMap<>();
            Map<String, Set<String>> ipPorts = new HashMap<>();
            Packet packet;
            while ((packet = handle.getNextPacket()) != null) {
                EthernetPacket ethPacket = packet.get(EthernetPacket.class);
                IpV4Packet ipPacket = packet.get(IpV4Packet.class);
                TransportPacket transportPacket = packet.get(TransportPacket.class);
                if (ethPacket == null || ipPacket == null || transportPacket == null) continue;

                String macAddr = ethPacket.getHeader().getSrcAddr().toString();
                String ipAddr = ipPacket.getHeader().getSrcAddr().toString().substring(1);
                String destIp = ipPacket.getHeader().getDstAddr().toString().substring(1);
                if (ipAddr.equals("127.0.0.1")) continue;
                int ttl = ipPacket.getHeader().getTtlAsInt();
                int srcPort = transportPacket.getHeader().getSrcPort().valueAsInt();
                int destPort = transportPacket.getHeader().getDstPort().valueAsInt();
                String protocol = transportPacket instanceof TcpPacket ? "TCP" : "UDP";

                String vendor = lookupVendor(macAddr);
                String os = detectOS(ttl);

                String commKey = String.format("%s:%d -> %s:%d [%s]", ipAddr, srcPort, destIp, destPort, protocol);
                Integer commCount = commCounts.getOrDefault(commKey, 0) + 1;
                commCounts.put(commKey, commCount);

                String protocolNameSrc = PORT_PROTOCOL_MAP.getOrDefault(srcPort + "_" + protocol, "UNKNOWN_PROTOCOL");
                String protocolNameDest = PORT_PROTOCOL_MAP.getOrDefault(destPort + "_" + protocol, "UNKNOWN_PROTOCOL");
                String protocolName = !protocolNameSrc.equals("UNKNOWN_PROTOCOL") ? protocolNameSrc : protocolNameDest;

                String commEntry = String.format("%s (%s) {%d}", commKey, protocolName, commCount);

                ipInfo.put(ipAddr, new String[]{macAddr, vendor, os});
                ipCommunications.put(commKey, commEntry);
                ipPorts.computeIfAbsent(ipAddr, k -> new HashSet<>()).add(srcPort + "_" + protocol);
                ipPorts.computeIfAbsent(ipAddr, k -> new HashSet<>()).add(destPort + "_" + protocol);
            }

            for (Map.Entry<String, String[]> entry : ipInfo.entrySet()) {
                String ipAddr = entry.getKey();
                String[] info = entry.getValue();
                System.out.printf("%s \n\tVendor: %s\n\tMAC: %s\n\tOS Guess: %s\n", ipAddr, info[1], info[0], info[2]);
                System.out.println("\tPorts & Protocols:");
                Set<String> ports = ipPorts.get(ipAddr);
                if (ports != null) {
                    for (String port : ports) {
                        String[] portProtocol = port.split("_");
                        String protocolName = PORT_PROTOCOL_MAP.get(port);
                        if (protocolName != null) {
                            System.out.printf("\t\tPort %s (%s)\n", portProtocol[0], protocolName);
                        }
                    }
                }
                System.out.println("\tCommunications:");
                for (Map.Entry<String, String> commEntry : ipCommunications.entrySet()) {
                    if (commEntry.getKey().startsWith(ipAddr)) {
                        System.out.printf("\t\t%s\n", commEntry.getValue());
                    }
                }
                System.out.println();
            }
        } catch (PcapNativeException | NotOpenException e) {
            e.printStackTrace();
        }
    }
}
