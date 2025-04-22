package org.example.PcapAnaysisOnJava;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.math.BigInteger;

public class PcapAnalyzer {
    public static void main(String[] args) {
        String pcapFilePath = "test.pcap"; 
        String outputCsvPath = "output.csv"; 

        try (FileInputStream fis = new FileInputStream(pcapFilePath);
             BufferedWriter csvWriter = new BufferedWriter(new FileWriter(outputCsvPath))) {
            csvWriter.write("Protocol,Source Port,Destination Port,Payload Length,First 1 Byte,First 2 Bytes,First 3 Bytes,First 5 Bytes,First 8 Bytes,First 16 Bytes");
            csvWriter.newLine();

            byte[] globalHeader = new byte[24];
            fis.read(globalHeader);

            ByteBuffer globalBuffer = ByteBuffer.wrap(globalHeader);
            globalBuffer.order(ByteOrder.LITTLE_ENDIAN); 

            int magicNumber = globalBuffer.getInt();
            if (magicNumber != 0xA1B2C3D4 && magicNumber != 0xD4C3B2A1) {
                throw new IllegalArgumentException("Geçersiz PCAP dosyası");
            }
            if (magicNumber == 0xD4C3B2A1) {
                globalBuffer.order(ByteOrder.BIG_ENDIAN);
            }

            while (fis.available() > 0) {
                byte[] packetHeader = new byte[16];
                fis.read(packetHeader);

                ByteBuffer packetBuffer = ByteBuffer.wrap(packetHeader).order(globalBuffer.order());
                int capturedLength = packetBuffer.getInt(8); 

                byte[] packetData = new byte[capturedLength];
                fis.read(packetData);

                parseEthernetFrame(packetData, csvWriter);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void parseEthernetFrame(byte[] packetData, BufferedWriter csvWriter) throws IOException {
        if (packetData.length < 14) {
            System.out.println("Geçersiz Ethernet çerçevesi (çok kısa)");
            return;
        }

        int etherType = ((packetData[12] & 0xFF) << 8) | (packetData[13] & 0xFF);

        if (etherType == 0x0800) { 
            parseIPv4Packet(packetData, 14, csvWriter);
        }
    }

    private static void parseIPv4Packet(byte[] packetData, int startOffset, BufferedWriter csvWriter) throws IOException {
        if (packetData.length < startOffset + 20) {
            System.out.println("Geçersiz IPv4 paketi (çok kısa)");
            return;
        }

        int ihl = (packetData[startOffset] & 0x0F) * 4; 

        int protocol = packetData[startOffset + 9] & 0xFF;
        if (protocol == 6) {
            parseTCPHeader(packetData, startOffset + ihl, csvWriter);
        } else if (protocol == 17) {
            parseUDPHeader(packetData, startOffset + ihl, csvWriter);
        }
    }

    private static void parseTCPHeader(byte[] packetData, int startOffset, BufferedWriter csvWriter) throws IOException {
        if (packetData.length < startOffset + 20) {
            System.out.println("Geçersiz TCP başlığı (çok kısa)");
            return;
        }

        int srcPort = ((packetData[startOffset] & 0xFF) << 8) | (packetData[startOffset + 1] & 0xFF);
        int dstPort = ((packetData[startOffset + 2] & 0xFF) << 8) | (packetData[startOffset + 3] & 0xFF);

        int payloadOffset = startOffset + 20; 
        int payloadLength = packetData.length - payloadOffset;

        String first1Byte = extractAndConvertToInteger(packetData, payloadOffset, 1);
        String first2Bytes = extractAndConvertToInteger(packetData, payloadOffset, 2);
        String first3Bytes = extractAndConvertToInteger(packetData, payloadOffset, 3);
        String first5Bytes = extractAndConvertToInteger(packetData, payloadOffset, 5);
        String first8Bytes = extractAndConvertToInteger(packetData, payloadOffset, 8);
        String first16Bytes = extractAndConvertToInteger(packetData, payloadOffset, 16);

        csvWriter.write(String.format("TCP,%d,%d,%d,%s,%s,%s,%s,%s,%s",
                srcPort, dstPort, payloadLength,
                first1Byte, first2Bytes, first3Bytes, first5Bytes, first8Bytes, first16Bytes));
        csvWriter.newLine();
    }

    private static void parseUDPHeader(byte[] packetData, int startOffset, BufferedWriter csvWriter) throws IOException {
        if (packetData.length < startOffset + 8) {
            System.out.println("Geçersiz UDP başlığı (çok kısa)");
            return;
        }

        int srcPort = ((packetData[startOffset] & 0xFF) << 8) | (packetData[startOffset + 1] & 0xFF);
        int dstPort = ((packetData[startOffset + 2] & 0xFF) << 8) | (packetData[startOffset + 3] & 0xFF);

        int payloadOffset = startOffset + 8; 
        int payloadLength = packetData.length - payloadOffset;

        String first1Byte = extractAndConvertToInteger(packetData, payloadOffset, 1);
        String first2Bytes = extractAndConvertToInteger(packetData, payloadOffset, 2);
        String first3Bytes = extractAndConvertToInteger(packetData, payloadOffset, 3);
        String first5Bytes = extractAndConvertToInteger(packetData, payloadOffset, 5);
        String first8Bytes = extractAndConvertToInteger(packetData, payloadOffset, 8);
        String first16Bytes = extractAndConvertToInteger(packetData, payloadOffset, 16);

        csvWriter.write(String.format("UDP,%d,%d,%d,%s,%s,%s,%s,%s,%s",
                srcPort, dstPort, payloadLength,
                first1Byte, first2Bytes, first3Bytes, first5Bytes, first8Bytes, first16Bytes));
        csvWriter.newLine();
    }


    private static String extractAndConvertToInteger(byte[] data, int offset, int length) {
        int availableLength = Math.min(length, data.length - offset);
        
        if (availableLength <= 0) {
            return "N/A"; 
        }
        
        byte[] extractedBytes = new byte[availableLength];
        System.arraycopy(data, offset, extractedBytes, 0, availableLength);
        
        BigInteger bigIntValue = new BigInteger(1, extractedBytes);
        return bigIntValue.toString();
    }


}
