/*
 ** Copyright 2015, Mohamed Naufal
 **
 ** Licensed under the Apache License, Version 2.0 (the "License");
 ** you may not use this file except in compliance with the License.
 ** You may obtain a copy of the License at
 **
 **     http://www.apache.org/licenses/LICENSE-2.0
 **
 ** Unless required by applicable law or agreed to in writing, software
 ** distributed under the License is distributed on an "AS IS" BASIS,
 ** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 ** See the License for the specific language governing permissions and
 ** limitations under the License.
 */

package com.innque.localvpn;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;

/**
 * Representation of an IP Packet
 */
// TODO: Reduce public mutability
public class Packet {

    public IP4Header ipHeader;
    public TCPHeader tcpHeader;
    public ByteBuffer buffer;


    public Packet(ByteBuffer buffer) throws UnknownHostException {
        this.ipHeader = new IP4Header(buffer);
        this.tcpHeader = new TCPHeader(buffer);
        this.buffer = buffer;
    }


    public void swapSourceAndDestination() {
        InetAddress newSourceAddress = ipHeader.destinationAddress;
        ipHeader.destinationAddress = ipHeader.sourceAddress;
        ipHeader.sourceAddress = newSourceAddress;
        int newSourcePort = tcpHeader.destinationPort;
        tcpHeader.destinationPort = tcpHeader.sourcePort;
        tcpHeader.sourcePort = newSourcePort;

    }

    public void updateTCPBuffer(byte flags, long sequenceNum, long ackNum, int payloadSize) {
        this.buffer.position(0);
        fillHeader();
        tcpHeader.flags = flags;
        this.buffer.put(IP4Header.SIZE + 13, flags);

        tcpHeader.sequenceNumber = sequenceNum;
        this.buffer.putInt(IP4Header.SIZE + 4, (int) sequenceNum);

        tcpHeader.acknowledgementNumber = ackNum;
        this.buffer.putInt(IP4Header.SIZE + 8, (int) ackNum);

        // Reset header size, since we don't need options
        byte dataOffset = (byte) (TCPHeader.SIZE << 2);
        System.out.println(dataOffset);
        tcpHeader.dataOffsetAndReserved = dataOffset;

        this.buffer.put(IP4Header.SIZE + 12, dataOffset);

        updateTCPChecksum(payloadSize);

        int ip4TotalLength = IP4Header.SIZE + TCPHeader.SIZE + payloadSize;
        this.buffer.putShort(2, (short) ip4TotalLength);
        ipHeader.totalLength = ip4TotalLength;

        updateIP4Checksum();
    }


    private void updateIP4Checksum() {
        ByteBuffer buffer = this.buffer.duplicate();
        buffer.position(0);

        // Clear previous checksum
        buffer.putShort(10, (short) 0);

        int ipLength = ipHeader.headerLength;
        int sum = 0;
        while (ipLength > 0) {
            sum += BitUtils.getUnsignedShort(buffer.getShort());
            ipLength -= 2;
        }
        while (sum >> 16 > 0)
            sum = (sum & 0xFFFF) + (sum >> 16);

        sum = ~sum;
        ipHeader.headerChecksum = sum;
        this.buffer.putShort(10, (short) sum);
    }

    private void updateTCPChecksum(int payloadSize) {
        int sum = 0;
        int tcpLength = TCPHeader.SIZE + payloadSize;

        // Calculate pseudo-header checksum
        ByteBuffer buffer = ByteBuffer.wrap(ipHeader.sourceAddress.getAddress());
        sum = BitUtils.getUnsignedShort(buffer.getShort()) + BitUtils.getUnsignedShort(buffer.getShort());

        buffer = ByteBuffer.wrap(ipHeader.destinationAddress.getAddress());
        sum += BitUtils.getUnsignedShort(buffer.getShort()) + BitUtils.getUnsignedShort(buffer.getShort());

        sum += IP4Header.TransportProtocol.TCP.getNumber() + tcpLength;

        buffer = this.buffer.duplicate();
        // Clear previous checksum
        buffer.putShort(IP4Header.SIZE + 16, (short) 0);

        // Calculate TCP segment checksum
        buffer.position(IP4Header.SIZE);
        while (tcpLength > 1) {
            sum += BitUtils.getUnsignedShort(buffer.getShort());
            tcpLength -= 2;
        }
        if (tcpLength > 0)
            sum += BitUtils.getUnsignedByte(buffer.get()) << 8;

        while (sum >> 16 > 0)
            sum = (sum & 0xFFFF) + (sum >> 16);

        sum = ~sum;
        tcpHeader.checksum = sum;
        this.buffer.putShort(IP4Header.SIZE + 16, (short) sum);
    }

    private void fillHeader() {
        ipHeader.fillHeader();
        tcpHeader.fillHeader();
    }


}
