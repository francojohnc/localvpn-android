package com.innque.localvpn;


import java.nio.ByteBuffer;

public class ConnectionTest {
    public void testSend() {
        String IPHeaderHex = "4500003c4867400040067430c0a8fe67c0a8fe6b";
        String TCPHeaderHex = "e6b222b860a0e96f00000000a002ffffd5020000020405b40402080a0055a1080000000001030307";
        byte[] bytes = BitUtils.toByteArray(IPHeaderHex + TCPHeaderHex);
        ByteBuffer buffer = ByteBuffer.allocate(1500);
        buffer.put(bytes);
        buffer.flip();
        Packet packet = new Packet(buffer);
    }
}