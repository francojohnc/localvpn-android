package com.innque.localvpn;

public class BitUtils {
    public static short getUnsignedByte(byte value) {
        return (short) (value & 0xFF);
    }

    public static int getUnsignedShort(short value) {
        return value & 0xFFFF;
    }

    public static long getUnsignedInt(int value) {
        return value & 0xFFFFFFFFL;
    }

    public static long checksum(long n, int k) {
        long sum = n;
        int mask = (1 << k) - 1;
        while (sum >> k > 0) {
            sum = (sum & mask) + (sum >> k);
        }
        sum = ~sum;
        return sum & mask;
    }

    public static byte[] toByteArray(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
}
