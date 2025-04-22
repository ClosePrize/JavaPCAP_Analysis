package org.example.PcapAnaysisOnJava;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class App {
    public static void main(String[] args) {
        String pcapFilePath = "test.pcap";
        int a = 0;

        try (FileInputStream fis = new FileInputStream(pcapFilePath)) {
            byte[] globalHeader = new byte[24];
            fis.read(globalHeader);

            ByteBuffer buffer = ByteBuffer.wrap(globalHeader);
            buffer.order(ByteOrder.LITTLE_ENDIAN); 

            while (fis.available() > 0) {
                byte[] packetHeader = new byte[16];
                fis.read(packetHeader);

                ByteBuffer headerBuffer = ByteBuffer.wrap(packetHeader).order(ByteOrder.LITTLE_ENDIAN);
                int capturedLength = headerBuffer.getInt(8); 

                if (capturedLength <= 0 || fis.available() < capturedLength) {
                    System.err.println("Invalid packet length, skipping...");
                    a++;
                    fis.skip(Math.max(0, capturedLength));
                    continue;
                }

                byte[] packetData = new byte[capturedLength];
                fis.read(packetData);

                if (packetData.length < 14) {
                    System.err.println("Packet is too short to contain Ethernet header, skipping...");
                    a++;
                    continue;
                }

                int etherType = ((packetData[12] & 0xFF) << 8) | (packetData[13] & 0xFF);
                if (etherType != 0x0800) { 
                    continue;
                }

                int ipHeaderStart = 14;
                if (packetData.length < ipHeaderStart + 20) {
                    System.err.println("Packet is too short to contain IPv4 header, skipping...");
                    a++;
                    continue;
                }

                int ipHeaderLength = (packetData[ipHeaderStart] & 0x0F) * 4; 
                String srcIp = (packetData[ipHeaderStart + 12] & 0xFF) + "." +
                               (packetData[ipHeaderStart + 13] & 0xFF) + "." +
                               (packetData[ipHeaderStart + 14] & 0xFF) + "." +
                               (packetData[ipHeaderStart + 15] & 0xFF);
                String dstIp = (packetData[ipHeaderStart + 16] & 0xFF) + "." +
                               (packetData[ipHeaderStart + 17] & 0xFF) + "." +
                               (packetData[ipHeaderStart + 18] & 0xFF) + "." +
                               (packetData[ipHeaderStart + 19] & 0xFF);

                int tcpHeaderStart = ipHeaderStart + ipHeaderLength;
                if (packetData.length < tcpHeaderStart + 20) {
                    System.err.println("Packet is too short to contain TCP header, skipping...");
                    a++;
                    continue;
                }

                int srcPort = ((packetData[tcpHeaderStart] & 0xFF) << 8) | (packetData[tcpHeaderStart + 1] & 0xFF);
                int dstPort = ((packetData[tcpHeaderStart + 2] & 0xFF) << 8) | (packetData[tcpHeaderStart + 3] & 0xFF);
                int tcpHeaderLength = ((packetData[tcpHeaderStart + 12] & 0xF0) >> 4) * 4; 
                int tcpPayloadLength = Math.max(0, capturedLength - (tcpHeaderStart + tcpHeaderLength));

                System.out.println("Source IP: " + srcIp);
                System.out.println("Destination IP: " + dstIp);
                System.out.println("Source Port: " + srcPort);
                System.out.println("Destination Port: " + dstPort);
                System.out.println("TCP Payload Length: " + tcpPayloadLength);
                System.out.println("----------------------------");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println(a);
    }
}
