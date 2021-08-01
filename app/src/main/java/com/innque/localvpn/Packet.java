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
    public static final int IP4_HEADER_SIZE = 20;
    public static final int TCP_HEADER_SIZE = 20;

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
        this.buffer.put(IP4_HEADER_SIZE + 13, flags);

        tcpHeader.sequenceNumber = sequenceNum;
        this.buffer.putInt(IP4_HEADER_SIZE + 4, (int) sequenceNum);

        tcpHeader.acknowledgementNumber = ackNum;
        this.buffer.putInt(IP4_HEADER_SIZE + 8, (int) ackNum);

        // Reset header size, since we don't need options
        byte dataOffset = (byte) (TCP_HEADER_SIZE << 2);
        System.out.println(dataOffset);
        tcpHeader.dataOffsetAndReserved = dataOffset;

        this.buffer.put(IP4_HEADER_SIZE + 12, dataOffset);

        updateTCPChecksum(payloadSize);

        int ip4TotalLength = IP4_HEADER_SIZE + TCP_HEADER_SIZE + payloadSize;
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
        int tcpLength = TCP_HEADER_SIZE + payloadSize;

        // Calculate pseudo-header checksum
        ByteBuffer buffer = ByteBuffer.wrap(ipHeader.sourceAddress.getAddress());
        sum = BitUtils.getUnsignedShort(buffer.getShort()) + BitUtils.getUnsignedShort(buffer.getShort());

        buffer = ByteBuffer.wrap(ipHeader.destinationAddress.getAddress());
        sum += BitUtils.getUnsignedShort(buffer.getShort()) + BitUtils.getUnsignedShort(buffer.getShort());

        sum += IP4Header.TransportProtocol.TCP.getNumber() + tcpLength;

        buffer = this.buffer.duplicate();
        // Clear previous checksum
        buffer.putShort(IP4_HEADER_SIZE + 16, (short) 0);

        // Calculate TCP segment checksum
        buffer.position(IP4_HEADER_SIZE);
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
        this.buffer.putShort(IP4_HEADER_SIZE + 16, (short) sum);
    }

    private void fillHeader() {
        ipHeader.fillHeader();
        tcpHeader.fillHeader();
    }

    public static class IP4Header {
        public byte version;
        public byte IHL;
        public int headerLength;
        public short typeOfService;
        public int totalLength;

        public int identificationAndFlagsAndFragmentOffset;

        public short TTL;
        private short protocolNum;
        public TransportProtocol protocol;
        public int headerChecksum;

        public InetAddress sourceAddress;
        public InetAddress destinationAddress;

        public int optionsAndPadding;

        private enum TransportProtocol {
            TCP(6),
            UDP(17),
            Other(0xFF);

            private int protocolNumber;

            TransportProtocol(int protocolNumber) {
                this.protocolNumber = protocolNumber;
            }

            private static TransportProtocol numberToEnum(int protocolNumber) {
                if (protocolNumber == 6)
                    return TCP;
                else if (protocolNumber == 17)
                    return UDP;
                else
                    return Other;
            }

            public int getNumber() {
                return this.protocolNumber;
            }
        }

        private ByteBuffer buffer;

        private IP4Header(ByteBuffer buffer) throws UnknownHostException {
            byte versionAndIHL = buffer.get();
            this.version = (byte) (versionAndIHL >> 4);
            this.IHL = (byte) (versionAndIHL & 0x0F);
            this.headerLength = this.IHL << 2;

            this.typeOfService = BitUtils.getUnsignedByte(buffer.get());
            this.totalLength = BitUtils.getUnsignedShort(buffer.getShort());

            this.identificationAndFlagsAndFragmentOffset = buffer.getInt();

            this.TTL = BitUtils.getUnsignedByte(buffer.get());
            this.protocolNum = BitUtils.getUnsignedByte(buffer.get());
            this.protocol = TransportProtocol.numberToEnum(protocolNum);
            this.headerChecksum = BitUtils.getUnsignedShort(buffer.getShort());

            byte[] addressBytes = new byte[4];
            buffer.get(addressBytes, 0, 4);
            this.sourceAddress = InetAddress.getByAddress(addressBytes);

            buffer.get(addressBytes, 0, 4);
            this.destinationAddress = InetAddress.getByAddress(addressBytes);
            this.buffer = buffer;
        }

        public void fillHeader() {
            this.buffer.put((byte) (this.version << 4 | this.IHL));
            this.buffer.put((byte) this.typeOfService);
            this.buffer.putShort((short) this.totalLength);

            this.buffer.putInt(this.identificationAndFlagsAndFragmentOffset);

            this.buffer.put((byte) this.TTL);
            this.buffer.put((byte) this.protocol.getNumber());
            this.buffer.putShort((short) this.headerChecksum);

            this.buffer.put(this.sourceAddress.getAddress());
            this.buffer.put(this.destinationAddress.getAddress());
        }

        @Override
        public String toString() {
            final StringBuilder sb = new StringBuilder("IP4Header{");
            sb.append("version=").append(version);
            sb.append(", IHL=").append(IHL);
            sb.append(", typeOfService=").append(typeOfService);
            sb.append(", totalLength=").append(totalLength);
            sb.append(", identificationAndFlagsAndFragmentOffset=").append(identificationAndFlagsAndFragmentOffset);
            sb.append(", TTL=").append(TTL);
            sb.append(", protocol=").append(protocolNum).append(":").append(protocol);
            sb.append(", headerChecksum=").append(headerChecksum);
            sb.append(", sourceAddress=").append(sourceAddress.getHostAddress());
            sb.append(", destinationAddress=").append(destinationAddress.getHostAddress());
            sb.append('}');
            return sb.toString();
        }
    }

    public static class TCPHeader {
        public static final int FIN = 0x01;
        public static final int SYN = 0x02;
        public static final int RST = 0x04;
        public static final int PSH = 0x08;
        public static final int ACK = 0x10;
        public static final int URG = 0x20;

        public int sourcePort;
        public int destinationPort;

        public long sequenceNumber;
        public long acknowledgementNumber;

        public byte dataOffsetAndReserved;
        public int headerLength;
        public byte flags;
        public int window;

        public int checksum;
        public int urgentPointer;

        public byte[] optionsAndPadding;
        private ByteBuffer buffer;

        private TCPHeader(ByteBuffer buffer) {
            this.sourcePort = BitUtils.getUnsignedShort(buffer.getShort());
            this.destinationPort = BitUtils.getUnsignedShort(buffer.getShort());

            this.sequenceNumber = BitUtils.getUnsignedInt(buffer.getInt());
            this.acknowledgementNumber = BitUtils.getUnsignedInt(buffer.getInt());

            this.dataOffsetAndReserved = buffer.get();
            this.headerLength = (this.dataOffsetAndReserved & 0xF0) >> 2;
            this.flags = buffer.get();
            this.window = BitUtils.getUnsignedShort(buffer.getShort());

            this.checksum = BitUtils.getUnsignedShort(buffer.getShort());
            this.urgentPointer = BitUtils.getUnsignedShort(buffer.getShort());

            int optionsLength = this.headerLength - TCP_HEADER_SIZE;
            if (optionsLength > 0) {
                optionsAndPadding = new byte[optionsLength];
                buffer.get(optionsAndPadding, 0, optionsLength);
            }
            this.buffer = buffer;
        }

        public boolean isFIN() {
            return (flags & FIN) == FIN;
        }

        public boolean isSYN() {
            return (flags & SYN) == SYN;
        }

        public boolean isRST() {
            return (flags & RST) == RST;
        }

        public boolean isPSH() {
            return (flags & PSH) == PSH;
        }

        public boolean isACK() {
            return (flags & ACK) == ACK;
        }

        public boolean isURG() {
            return (flags & URG) == URG;
        }

        private void fillHeader() {
            this.buffer.putShort((short) sourcePort);
            this.buffer.putShort((short) destinationPort);

            this.buffer.putInt((int) sequenceNumber);
            this.buffer.putInt((int) acknowledgementNumber);

            this.buffer.put(dataOffsetAndReserved);
            this.buffer.put(flags);
            this.buffer.putShort((short) window);

            this.buffer.putShort((short) checksum);
            this.buffer.putShort((short) urgentPointer);
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder("TCPHeader{");
            sb.append("sourcePort:").append(sourcePort);
            sb.append(",destinationPort:").append(destinationPort);
            sb.append(",sequenceNumber:").append(sequenceNumber);
            sb.append(",acknowledgementNumber:").append(acknowledgementNumber);
            sb.append(",offset:").append(headerLength);
            if (isFIN()) sb.append(",FIN:").append(true);
            if (isSYN()) sb.append(",SYN:").append(true);
            if (isRST()) sb.append(",RST:").append(true);
            if (isPSH()) sb.append(",PSH:").append(true);
            if (isACK()) sb.append(",ACK:").append(true);
            if (isURG()) sb.append(",URG:").append(true);
            sb.append(",window:").append(window);
            sb.append(",checksum:").append(checksum);
            sb.append('}');
            return sb.toString();
        }

    }


    private static class BitUtils {
        private static short getUnsignedByte(byte value) {
            return (short) (value & 0xFF);
        }

        private static int getUnsignedShort(short value) {
            return value & 0xFFFF;
        }

        private static long getUnsignedInt(int value) {
            return value & 0xFFFFFFFFL;
        }
    }


    /* ip v4 length */
    public int getLength() {
        this.buffer.position(0);
        short versionAndHelen = BitUtils.getUnsignedByte(this.buffer.get());
        int IHL = versionAndHelen & 0x0F;
        return IHL * 4;
    }

    public void setFlags(byte flags) {
        this.buffer.position(this.getLength() + 13);
        this.buffer.put(flags);
    }

    public void setSequenceNumber(int sequenceNumber) {
        this.buffer.position(this.getLength() + 4);
        this.buffer.putInt(sequenceNumber);
    }

    public void setAcknowledgmentNumber(int acknowledgmentNumber) {
        this.buffer.position(this.getLength() + 8);
        this.buffer.putInt(acknowledgmentNumber);
    }

    public void setOffset(int offset) {
        this.buffer.position(this.getLength() + 12);
        this.buffer.put((byte) ((offset / 4) << 4));
    }

    public void setData(byte[] bytes) {
        int length = this.getLength(); // IP Header length
        int offset = this.getOffset(); // TCP Header length
        int position = length + offset;
        this.buffer.position(position);
        this.buffer.put(bytes);
    }

    public int getOffset() {
        this.buffer.position(this.getLength() + 12);
        short offsetAndReserved = BitUtils.getUnsignedByte(buffer.get());
        return (offsetAndReserved >> 4) * 4;
    }
}
