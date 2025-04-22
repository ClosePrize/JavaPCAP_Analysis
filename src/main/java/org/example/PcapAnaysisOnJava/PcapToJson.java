package org.example.PcapAnaysisOnJava;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.pcap4j.core.*;
import org.pcap4j.packet.*;

import java.io.*;
import java.util.*;

public class PcapToJson {
    private static final String PCAP_FILE = "test.pcap";
    private static final String OUI_FILE = "mac-vendor.txt";
    private static final Map<Integer, String> OUI_MAP = new HashMap<>();

    private static final Map<String, String> PORT_PROTOCOL_MAP = new HashMap<>();
    static {
    	PORT_PROTOCOL_MAP.put("20_TCP", "FTP Data Transfer [TCP]");
    	PORT_PROTOCOL_MAP.put("21_TCP", "FTP Control [TCP]");
    	PORT_PROTOCOL_MAP.put("22_TCP", "SSH [TCP]");
    	PORT_PROTOCOL_MAP.put("23_TCP", "Telnet [TCP]");
    	PORT_PROTOCOL_MAP.put("25_TCP", "SMTP [TCP]");
    	PORT_PROTOCOL_MAP.put("53_TCP", "DNS [TCP]");
    	PORT_PROTOCOL_MAP.put("53_UDP", "DNS [UDP]");
    	PORT_PROTOCOL_MAP.put("67_UDP", "DHCP Server [UDP]");
    	PORT_PROTOCOL_MAP.put("68_UDP", "DHCP Client [UDP]");
    	PORT_PROTOCOL_MAP.put("69_UDP", "TFTP [UDP]");
    	PORT_PROTOCOL_MAP.put("80_TCP", "HTTP [TCP]");
    	PORT_PROTOCOL_MAP.put("110_TCP", "POP3 [TCP]");
    	PORT_PROTOCOL_MAP.put("123_UDP", "NTP [UDP]");
    	PORT_PROTOCOL_MAP.put("143_TCP", "IMAP [TCP]");
    	PORT_PROTOCOL_MAP.put("161_UDP", "SNMP [UDP]");
    	PORT_PROTOCOL_MAP.put("162_UDP", "SNMP Trap [UDP]");
    	PORT_PROTOCOL_MAP.put("179_TCP", "BGP [TCP]");
    	PORT_PROTOCOL_MAP.put("443_TCP", "HTTPS [TCP]");
    	PORT_PROTOCOL_MAP.put("445_TCP", "Microsoft-DS [TCP]");
    	PORT_PROTOCOL_MAP.put("465_TCP", "SMTPS [TCP]");
    	PORT_PROTOCOL_MAP.put("514_UDP", "Syslog [UDP]");
    	PORT_PROTOCOL_MAP.put("515_TCP", "Printer Spooler [TCP]");
    	PORT_PROTOCOL_MAP.put("520_UDP", "RIP [UDP]");
    	PORT_PROTOCOL_MAP.put("587_TCP", "SMTP Submission [TCP]");
    	PORT_PROTOCOL_MAP.put("623_UDP", "ASF Remote Management and Control Protocol [UDP]");
    	PORT_PROTOCOL_MAP.put("993_TCP", "IMAPS [TCP]");
    	PORT_PROTOCOL_MAP.put("995_TCP", "POP3S [TCP]");
    	PORT_PROTOCOL_MAP.put("102_TCP", "ISO-TSAP [TCP]");
    	PORT_PROTOCOL_MAP.put("1080_TCP", "SOCKS Proxy [TCP]");
    	PORT_PROTOCOL_MAP.put("1433_TCP", "Microsoft SQL Server [TCP]");
    	PORT_PROTOCOL_MAP.put("1521_TCP", "Oracle Database [TCP]");
    	PORT_PROTOCOL_MAP.put("1723_TCP", "PPTP [TCP]");
    	PORT_PROTOCOL_MAP.put("1883_TCP", "MQTT [TCP]");
    	PORT_PROTOCOL_MAP.put("2404_TCP", "IEC 60870-5-104 [TCP]");
    	PORT_PROTOCOL_MAP.put("3306_TCP", "MySQL [TCP]");
    	PORT_PROTOCOL_MAP.put("3389_TCP", "RDP [TCP]");
    	PORT_PROTOCOL_MAP.put("5432_TCP", "PostgreSQL [TCP]");
    	PORT_PROTOCOL_MAP.put("5631_TCP", "pcAnywhere [TCP]");
    	PORT_PROTOCOL_MAP.put("5632_UDP", "pcAnywhere [UDP]");
    	PORT_PROTOCOL_MAP.put("5900_TCP", "VNC [TCP]");
    	PORT_PROTOCOL_MAP.put("6379_TCP", "Redis [TCP]");
    	PORT_PROTOCOL_MAP.put("8080_TCP", "HTTP Proxy [TCP]");
    	PORT_PROTOCOL_MAP.put("8443_TCP", "HTTPS Alt [TCP]");
    	PORT_PROTOCOL_MAP.put("8883_TCP", "Secure MQTT [TCP]");
    	PORT_PROTOCOL_MAP.put("1900_UDP", "SSDP [UDP]");
    	PORT_PROTOCOL_MAP.put("5353_UDP", "mDNS [UDP]");
    	PORT_PROTOCOL_MAP.put("1812_UDP", "RADIUS Authentication [UDP]");
    	PORT_PROTOCOL_MAP.put("1813_UDP", "RADIUS Accounting [UDP]");
    	PORT_PROTOCOL_MAP.put("3268_TCP", "Global Catalog LDAP [TCP]");
    	PORT_PROTOCOL_MAP.put("3269_TCP", "Global Catalog LDAP over SSL [TCP]");
    	PORT_PROTOCOL_MAP.put("137_UDP", "NetBIOS Name Service [UDP]");
    	PORT_PROTOCOL_MAP.put("138_UDP", "NetBIOS Datagram Service [UDP]");
    	PORT_PROTOCOL_MAP.put("139_TCP", "NetBIOS Session Service [TCP]");
    	PORT_PROTOCOL_MAP.put("500_UDP", "IKE [UDP]");
    	PORT_PROTOCOL_MAP.put("4500_UDP", "NAT-T [UDP]");
    	PORT_PROTOCOL_MAP.put("1194_UDP", "OpenVPN [UDP]");
    	PORT_PROTOCOL_MAP.put("1194_TCP", "OpenVPN [TCP]");
    	PORT_PROTOCOL_MAP.put("563_TCP", "NNTP over SSL [TCP]");
    	PORT_PROTOCOL_MAP.put("636_TCP", "LDAPS [TCP]");
    	PORT_PROTOCOL_MAP.put("993_TCP", "IMAP over SSL [TCP]");
    	PORT_PROTOCOL_MAP.put("995_TCP", "POP3 over SSL [TCP]");
    	PORT_PROTOCOL_MAP.put("2049_TCP", "NFS [TCP]");
    	PORT_PROTOCOL_MAP.put("2049_UDP", "NFS [UDP]");
    	PORT_PROTOCOL_MAP.put("3306_TCP", "MySQL [TCP]");
    	PORT_PROTOCOL_MAP.put("6379_TCP", "Redis [TCP]");
    	PORT_PROTOCOL_MAP.put("11211_TCP", "Memcached [TCP]");
    	PORT_PROTOCOL_MAP.put("11211_UDP", "Memcached [UDP]");
    	PORT_PROTOCOL_MAP.put("27017_TCP", "MongoDB [TCP]");
    	PORT_PROTOCOL_MAP.put("5000_TCP", "UPnP [TCP]");
    	PORT_PROTOCOL_MAP.put("5000_UDP", "UPnP [UDP]");
    	PORT_PROTOCOL_MAP.put("5357_TCP", "WS-Discovery [TCP]");
    	PORT_PROTOCOL_MAP.put("5357_UDP", "WS-Discovery [UDP]");
    	PORT_PROTOCOL_MAP.put("49152_TCP", "Microsoft DCOM [TCP]");
    	PORT_PROTOCOL_MAP.put("49152_UDP", "Microsoft DCOM [UDP]");
    	PORT_PROTOCOL_MAP.put("49153_TCP", "Microsoft DCOM [TCP]");
    	PORT_PROTOCOL_MAP.put("49153_UDP", "Microsoft DCOM [UDP]");
    	PORT_PROTOCOL_MAP.put("49154_TCP", "Microsoft DCOM [TCP]");
    	PORT_PROTOCOL_MAP.put("49154_UDP", "Microsoft DCOM [UDP]");
    	PORT_PROTOCOL_MAP.put("49155_TCP", "Microsoft DCOM [TCP]");
    	PORT_PROTOCOL_MAP.put("49155_UDP", "Microsoft DCOM [UDP]");
    	PORT_PROTOCOL_MAP.put("49156_TCP", "Microsoft DCOM [TCP]");
    	PORT_PROTOCOL_MAP.put("49156_UDP", "Microsoft DCOM [UDP]");
    	PORT_PROTOCOL_MAP.put("49157_TCP", "Microsoft DCOM [TCP]");
    	PORT_PROTOCOL_MAP.put("49157_UDP", "Microsoft DCOM [UDP]");
    	PORT_PROTOCOL_MAP.put("49158_TCP", "Microsoft DCOM [TCP]");
    	PORT_PROTOCOL_MAP.put("49158_UDP", "Microsoft DCOM [UDP]");
    	PORT_PROTOCOL_MAP.put("49159_TCP", "Microsoft DCOM [TCP]");
    	PORT_PROTOCOL_MAP.put("49159_UDP", "Microsoft DCOM [UDP]");
    	PORT_PROTOCOL_MAP.put("49160_TCP", "Microsoft DCOM [TCP]");
    	PORT_PROTOCOL_MAP.put("49160_UDP", "Microsoft DCOM [UDP]");
    	PORT_PROTOCOL_MAP.put("49161_TCP", "Microsoft DCOM [TCP]");
    	PORT_PROTOCOL_MAP.put("49161_UDP", "Microsoft DCOM [UDP]");
    	PORT_PROTOCOL_MAP.put("49162_TCP", "Microsoft DCOM [TCP]");
    	PORT_PROTOCOL_MAP.put("49162_UDP", "Microsoft DCOM [UDP]");
    	PORT_PROTOCOL_MAP.put("49163_TCP", "Microsoft DCOM [TCP]"); 	 
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
    
    private static String detectDeviceType(Map<String, List<String>> ports) {
        Set<String> plcPorts = Set.of("502_TCP", "2404_TCP", "4840_TCP", "44818_TCP");
        Set<String> iedPorts = Set.of("102_TCP", "2404_TCP");
        Set<String> scadaPorts = Set.of("1911_TCP", "18245_TCP", "2455_TCP", "4911_TCP");
        Set<String> workstationPorts = Set.of("22_TCP", "80_TCP", "443_TCP", "3389_TCP");

        boolean isPLC = ports.keySet().stream().anyMatch(port -> plcPorts.contains(port + "_TCP") || plcPorts.contains(port + "_UDP"));
        boolean isIED = ports.keySet().stream().anyMatch(port -> iedPorts.contains(port + "_TCP") || iedPorts.contains(port + "_UDP"));
        boolean isSCADA = ports.keySet().stream().anyMatch(port -> scadaPorts.contains(port + "_TCP") || scadaPorts.contains(port + "_UDP"));
        boolean isWorkstation = ports.keySet().stream().anyMatch(port -> workstationPorts.contains(port + "_TCP") || workstationPorts.contains(port + "_UDP"));

        if (isPLC) return "PLC";
        if (isIED) return "IED";
        if (isSCADA) return "SCADA";
        if (isWorkstation) return "Workstation";

        return "Unknown";  
    }

    private static void analyzePcap(String pcapFile) {
        try (PcapHandle handle = Pcaps.openOffline(pcapFile)) {
            Map<String, Map<String, Object>> jsonOutput = new HashMap<>();
            Packet packet;

            while ((packet = handle.getNextPacket()) != null) {
                EthernetPacket ethPacket = packet.get(EthernetPacket.class);
                IpV4Packet ipPacket = packet.get(IpV4Packet.class);
                TransportPacket transportPacket = packet.get(TransportPacket.class);
                if (ethPacket == null || ipPacket == null || transportPacket == null) continue;

                String srcMac = ethPacket.getHeader().getSrcAddr().toString();
                String srcIp = ipPacket.getHeader().getSrcAddr().toString().substring(1);
                String dstIp = ipPacket.getHeader().getDstAddr().toString().substring(1);
                if (srcIp.equals("127.0.0.1") || dstIp.equals("127.0.0.1")) continue;
                
                int ttl = ipPacket.getHeader().getTtlAsInt();
                int srcPort = transportPacket.getHeader().getSrcPort().valueAsInt();
                String protocol = transportPacket instanceof TcpPacket ? "TCP" : "UDP";

                String vendor = lookupVendor(srcMac);
                String os = detectOS(ttl);
                String portKey = srcPort + "_" + protocol;
                String protocolName = PORT_PROTOCOL_MAP.getOrDefault(portKey, "UNKNOWN_PROTOCOL");

                jsonOutput.putIfAbsent(srcIp, new HashMap<>());
                Map<String, Object> deviceInfo = jsonOutput.get(srcIp);
                deviceInfo.put("mac_address", srcMac);
                deviceInfo.put("vendor", vendor);
                deviceInfo.put("OS", os);

                @SuppressWarnings("unchecked")
                Map<String, Set<String>> ports = (Map<String, Set<String>>) deviceInfo.computeIfAbsent("ports", k -> new HashMap<>());
                ports.putIfAbsent(String.valueOf(srcPort), new HashSet<>());
                ports.get(String.valueOf(srcPort)).add(protocolName);

                @SuppressWarnings("unchecked")
                List<Map<String, List<String>>> connections = (List<Map<String, List<String>>>) deviceInfo.computeIfAbsent("connections", k -> new ArrayList<>());

                boolean connectionExists = false;
                for (Map<String, List<String>> connection : connections) {
                    if (connection.containsKey(dstIp)) {
                        connection.get(dstIp).add(protocolName);
                        connectionExists = true;
                        break;
                    }
                }

                if (!connectionExists) {
                    Map<String, List<String>> newConnection = new HashMap<>();
                    newConnection.put(dstIp, new ArrayList<>(List.of(protocolName)));
                    connections.add(newConnection);
                }

                Map<String, List<String>> convertedPorts = new HashMap<>();
                for (Map.Entry<String, Set<String>> entry : ports.entrySet()) {
                    convertedPorts.put(entry.getKey(), new ArrayList<>(entry.getValue()));
                }
                String deviceType = detectDeviceType(convertedPorts);

                deviceInfo.put("device_type", deviceType);
            }

            writeJsonToFile(jsonOutput);
        } catch (PcapNativeException | NotOpenException e) {
            e.printStackTrace();
        }
    }


    private static void writeJsonToFile(Map<String, Map<String, Object>> jsonData) {
        try (FileWriter writer = new FileWriter("output.json")) {
            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            gson.toJson(jsonData, writer);
            System.out.println("JSON output saved to output.json");
        } catch (IOException e) {
            System.err.println("Error writing JSON file: " + e.getMessage());
        }
    }
}
