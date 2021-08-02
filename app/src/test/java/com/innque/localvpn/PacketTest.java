package com.innque.localvpn;

import org.junit.Test;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;

import static org.junit.Assert.*;

public class PacketTest {
    @Test
    public void testFromHexSYN() throws UnknownHostException {
        String IPHeaderHex = "4500003c4867400040067430c0a8fe67c0a8fe6b";
        String TCPHeaderHex = "e6b222b860a0e96f00000000a002ffffd5020000020405b40402080a0055a1080000000001030307";
        byte[] bytes = BitUtils.toByteArray(IPHeaderHex + TCPHeaderHex);


        ByteBuffer buffer = ByteBuffer.allocate(1500);
        buffer.put(bytes);
        buffer.flip();
        Packet packet = new Packet(buffer);
        packet.updateTCPBuffer((byte) (TCPHeader.SYN + TCPHeader.ACK), 2, 4, 0);
        buffer.flip();
        assertEquals(buffer.position(), 0);
        assertEquals(buffer.limit(), 40);
//        // IP Header
        assertEquals(packet.ipHeader.getVersion(), 4);
        assertEquals(packet.ipHeader.getLength(), 20);
        assertEquals(packet.ipHeader.getType(), 0);
        assertEquals(packet.ipHeader.getTotalLength(), 40); // 60
        assertEquals(packet.ipHeader.getIdentification(), 18535);
        assertEquals(packet.ipHeader.getFlags(), 2);
        assertEquals(packet.ipHeader.getOffset(), 0);
        assertEquals(packet.ipHeader.getTTL(), 64);
        assertEquals(packet.ipHeader.getProtocol(), 6);
        assertEquals(packet.ipHeader.getChecksum(), 29764); // 29744
        assertEquals(packet.ipHeader.checksum(), 29764); // 29744
        assertEquals(packet.ipHeader.getSourceAddress(), InetAddress.getByName("192.168.254.103"));
        assertEquals(packet.ipHeader.getDestinationAddress(), InetAddress.getByName("192.168.254.107"));

//        // TCP Header
        assertEquals(packet.tcpHeader.getSourcePort(), 59058);
        assertEquals(packet.tcpHeader.getDestinationPort(), 8888);
        assertEquals(packet.tcpHeader.getSequenceNumber(), 2); // 1621158255
        assertEquals(packet.tcpHeader.getAcknowledgmentNumber(), 4); // 0
        assertEquals(packet.tcpHeader.getOffset(), 20); // 40
        assertEquals(packet.tcpHeader.getFlags(), 18); // 2
        assertEquals(packet.tcpHeader.isFIN(), false);
        assertEquals(packet.tcpHeader.isSYN(), true); // true
        assertEquals(packet.tcpHeader.isRST(), false);
        assertEquals(packet.tcpHeader.isPSH(), false);
        assertEquals(packet.tcpHeader.isACK(), true); // false
        assertEquals(packet.tcpHeader.isURG(), false);
        assertEquals(packet.tcpHeader.getWindow(), 65535);
        assertEquals(packet.tcpHeader.getChecksum(), 10301); // 54530
//        assertEquals(packet.tcpHeader.checksum(0), 10301); // 54530
        assertEquals(packet.tcpHeader.getUrgentPointer(), 0); // 0

    }
}