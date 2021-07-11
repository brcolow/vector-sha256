package com.brcolow.vectorsha256;

import jdk.incubator.vector.ByteVector;
import jdk.incubator.vector.IntVector;
import jdk.incubator.vector.VectorOperators;
import jdk.incubator.vector.VectorShuffle;
import jdk.incubator.vector.VectorSpecies;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.function.BiFunction;

/**
 * https://github.com/bitcoin/bitcoin/blob/7fcf53f7b4524572d1d0c9a5fdc388e87eb02416/src/crypto/sha256.h
 * https://github.com/bitcoin/bitcoin/blob/7fcf53f7b4524572d1d0c9a5fdc388e87eb02416/src/crypto/sha256.cpp
 * https://github.com/bitcoin/bitcoin/blob/7fcf53f7b4524572d1d0c9a5fdc388e87eb02416/src/crypto/sha256_avx2.cpp
 * https://github.com/bcgit/bc-java/blob/bc3b92f1f0e78b82e2584c5fb4b226a13e7f8b3b/core/src/main/java/org/bouncycastle/crypto/digests/SHA256Digest.java
 * https://github.com/bcgit/bc-java/blob/bc3b92f1f0e78b82e2584c5fb4b226a13e7f8b3b/core/src/main/java/org/bouncycastle/crypto/digests/GeneralDigest.java
 * https://github.com/openjdk/jdk/blob/739769c8fc4b496f08a92225a12d07414537b6c0/src/java.base/share/classes/sun/security/provider/SHA2.java#L250
 *
 * Non double implementation:
 * https://github.com/patrykwnosuch/cpuminer-nosuch/blob/f5d602ea58b12352bdd341df06422c21b4ad7cd2/algo/sha/sha2-hash-4way.c#L440
 *
 * Intel paper about multi-buffer SHA2:
 * https://www.intel.com/content/dam/www/public/us/en/documents/white-papers/sha-256-implementations-paper.pdf
 * https://www.intel.com/content/dam/www/public/us/en/documents/white-papers/communications-ia-multi-buffer-paper.pdf
 */
public class VectorSHA256 {
    static final VectorSpecies<Integer> SPECIES_64 = IntVector.SPECIES_64;
    static final VectorSpecies<Integer> SPECIES_128 = IntVector.SPECIES_128;
    static final VectorSpecies<Integer> SPECIES_256 = IntVector.SPECIES_256;

    public static void main(String[] args) throws NoSuchAlgorithmException {
        byte[] toHash = (
                "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxy" +
                "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxy" +
                "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxy" +
                "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxy")
                .getBytes(StandardCharsets.US_ASCII);
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        SHA2.SHA256 sha256 = new SHA2.SHA256();
        sha256.engineUpdate(toHash, 0, toHash.length);
        byte[] jdkCopyHash = sha256.engineDigest();
        byte[] jdkHash = digest.digest(toHash);
        if (!Arrays.equals(jdkCopyHash, jdkHash)) {
            throw new RuntimeException("JDK and JDK copy hash did not match!");
        }
        System.out.println("JDK hash: " + bytesToHex(jdkHash));
        System.out.println("JDK copy hash: " + bytesToHex(jdkCopyHash));
        byte[] out = new byte[32];
        Sha256Digest sha256Digest = new Sha256Digest();

        sha256Digest.update(toHash, 0, toHash.length);
        sha256Digest.digest(out, 0, 32);
        System.out.println("hash out: " + bytesToHex(out));
    }

    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    public static class Sha256Digest {
        private final int[] H;
        // buffer to store partial blocks, up to 64 bytes large
        private final byte[] buffer;
        // offset into buffer
        private int bufOfs;
        // size of the input to the compression function (transform) in bytes
        private final int blockSize8x = 64 * 8;
        private final int blockSize4x = 64 * 4;
        private final int blockSize2x = 64 * 2;
        private final int blockSize =   64;
        // length of the message digest in bytes
        private final int digestLength = 32;
        private long bytesProcessed;
        static final byte[] padding;

        static {
            padding = new byte[64];
            padding[0] = (byte)0x80;
        }

        static final class BE {
            static final VarHandle INT_ARRAY
                    = MethodHandles.byteArrayViewVarHandle(int[].class,
                    ByteOrder.BIG_ENDIAN).withInvokeExactBehavior();

        }

        static final class LE {
            static final VarHandle INT_ARRAY
                    = MethodHandles.byteArrayViewVarHandle(int[].class,
                    ByteOrder.LITTLE_ENDIAN).withInvokeExactBehavior();
        }

        private static final int[] INITIAL_HASHES = {
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        };

        public Sha256Digest() {
            H = new int[8];
            buffer = new byte[blockSize];
            resetHashes();
        }

        public void digest(byte[] out, int ofs, int len) {
            if (len < digestLength) {
                throw new IllegalArgumentException("Length must be at least "
                        + digestLength + " for SHA-256 digests");
            }
            if (ofs < 0 || ofs > out.length - len) {
                throw new IllegalArgumentException("Buffer too short to store digest");
            }
            if (bytesProcessed < 0) {
                reset();
            }
            long bitsProcessed = bytesProcessed << 3;
            int index = (int) bytesProcessed & 0x3f;
            int padLen = (index < 56) ? (56 - index) : (120 - index);
            update(padding, 0, padLen);

            BE.INT_ARRAY.set(buffer, 56, (int) (bitsProcessed >>> 32));
            BE.INT_ARRAY.set(buffer, 60, (int) bitsProcessed);
            transform(buffer);
            byte[] hash = new byte[digestLength];
            intArrToBytesBE(H, hash, digestLength);
            System.out.println("hash: " + bytesToHex(hash));
            System.arraycopy(hash, 0, out, ofs, digestLength);
            bytesProcessed = -1;
        }

        private void intArrToBytesBE(int[] in, byte[] out, int length) {
            int inOffset = 0;
            int outOffset = 0;
            while (outOffset < length) {
                BE.INT_ARRAY.set(out, outOffset, in[inOffset++]);
                outOffset += 4;
            }
        }

        public void reset() {
            resetHashes();
        }

        private void resetHashes() {
            H[0] = INITIAL_HASHES[0];
            H[1] = INITIAL_HASHES[1];
            H[2] = INITIAL_HASHES[2];
            H[3] = INITIAL_HASHES[3];
            H[4] = INITIAL_HASHES[4];
            H[5] = INITIAL_HASHES[5];
            H[6] = INITIAL_HASHES[6];
            H[7] = INITIAL_HASHES[7];
        }

        public void update(byte in) {
            // TODO
        }

        public void update(byte[] in, int inOff, int len) {
            if (len == 0) {
                return;
            }
            if ((inOff < 0) || (len < 0) || (inOff > in.length - len)) {
                throw new ArrayIndexOutOfBoundsException();
            }
            if (bytesProcessed < 0) {
                resetHashes();
            }
            bytesProcessed += len;
            if (bufOfs != 0) {
                // TODO (used when doing multiple update calls to digest object).
                System.out.println("bufOfs != 0");
                int n = Math.min(len, blockSize - bufOfs);
                System.arraycopy(in, inOff, buffer, bufOfs, n);
                bufOfs += n;
                inOff += n;
                len -= n;
                if (bufOfs >= blockSize) {
                    // TODO check blockSize8x, 4x, 2x.
                    // compress completed block now
                    // JDK does: implCompress(buffer, 0);
                    transform_multi_way(buffer, SPECIES_256, this::read8);
                    bufOfs = 0;
                }
            }

            if (len >= blockSize8x) {
                System.out.println("len >= blockSize8x");
                int limit = inOff + len;
                for (; inOff < limit; inOff += blockSize8x) {
                    transform_multi_way(in, SPECIES_256, this::read8);
                    byte[] hash = new byte[digestLength];
                    intArrToBytesBE(H, hash, digestLength);
                    System.out.println("After 8way transform (compress): ");
                    System.out.println("H[0] = " + bytesToHex(intToBytesBE(H[0])));
                    System.out.println("H[1] = " + bytesToHex(intToBytesBE(H[1])));
                    System.out.println("H[2] = " + bytesToHex(intToBytesBE(H[2])));
                    System.out.println("H[3] = " + bytesToHex(intToBytesBE(H[3])));
                    System.out.println("H[4] = " + bytesToHex(intToBytesBE(H[4])));
                    System.out.println("H[5] = " + bytesToHex(intToBytesBE(H[5])));
                    System.out.println("H[6] = " + bytesToHex(intToBytesBE(H[6])));
                    System.out.println("H[7] = " + bytesToHex(intToBytesBE(H[7])));
                    System.out.println("H[0] = " + H[0]);
                    System.out.println("H[1] = " + H[1]);
                    System.out.println("H[2] = " + H[2]);
                    System.out.println("H[3] = " + H[3]);
                    System.out.println("H[4] = " + H[4]);
                    System.out.println("H[5] = " + H[5]);
                    System.out.println("H[6] = " + H[6]);
                    System.out.println("H[7] = " + H[7]);
                    System.out.println("To match JDK impl after 8 rounds should be:");
                    System.out.println("H[0] = 993071969\n" +
                            "H[1] = 713321891\n" +
                            "H[2] = 668883598\n" +
                            "H[3] = 323462243\n" +
                            "H[4] = -1670923311\n" +
                            "H[5] = 1992375618\n" +
                            "H[6] = 1610520989\n" +
                            "H[7] = 103409777");
                    System.out.println("H[] after 8way transform: " + bytesToHex(hash));
                }
                len = limit - inOff;
                System.out.println("len is now: " + len);
            }

            if (len >= blockSize4x) {
                int limit = inOff + len;
                for (; inOff <= limit; inOff += blockSize4x) {
                    transform_multi_way(in, SPECIES_128, this::read4);
                    byte[] hash = new byte[digestLength];
                    intArrToBytesBE(H, hash, digestLength);
                    System.out.println("H[] after 4way transform: " + bytesToHex(hash));
                }
                len = limit - inOff;
            }

            if (len >= blockSize2x) {
                int limit = inOff + len;
                for (; inOff <= limit; inOff += blockSize2x) {
                    transform_multi_way(in, SPECIES_64, this::read2);
                    byte[] hash = new byte[digestLength];
                    intArrToBytesBE(H, hash, digestLength);
                    System.out.println("H[] after 2way transform: " + bytesToHex(hash));
                }
                len = limit - inOff;
            }

            while (len >= blockSize) {
                int limit = inOff + len;
                for (; inOff <= limit; inOff += blockSize) {
                    transform(in);
                    byte[] hash = new byte[digestLength];
                    intArrToBytesBE(H, hash, digestLength);
                    System.out.println("H[] after single (1way) transform: " + bytesToHex(hash));
                }
                len = limit - inOff;
            }
            // copy remainder to buffer
            if (len > 0) {
                System.arraycopy(in, inOff, buffer, 0, len);
                bufOfs = len;
            }
        }

        IntVector add(IntVector x, IntVector y) {
            return x.add(y);
        }

        IntVector add(IntVector x, IntVector y, IntVector z, IntVector w) {
            return add(add(x, y), add(z, w));
        }

        IntVector inc(IntVector x, IntVector y, IntVector z, IntVector w) {
            return add(x, y, z, w);
        }

        IntVector xor(IntVector x, IntVector y) {
            return x.lanewise(VectorOperators.XOR, y);
        }

        IntVector xor(IntVector x, IntVector y, IntVector z) {
            return xor(xor(x, y), z);
        }

        IntVector or(IntVector x, IntVector y) {
            return x.or(y);
        }

        IntVector and(IntVector x, IntVector y) {
            return x.and(y);
        }

        IntVector shR(IntVector x, int n) {
            return x.lanewise(VectorOperators.LSHR, n);
        }

        IntVector shL(IntVector x, int n) {
            return x.lanewise(VectorOperators.LSHL, n);
        }

        IntVector ch(IntVector x, IntVector y, IntVector z) {
            return xor(z, and(x, xor(y, z)));
        }

        int ch(int x, int y, int z) {
            return z ^ (x & (y ^ z));
        }

        IntVector maj(IntVector x, IntVector y, IntVector z) {
            return or(and(x, y), and(z, or(x, y)));
        }

        int maj(int x, int y, int z) {
            return (x & y) | (z & (x | y));
        }

        IntVector Sigma0(IntVector x) {
            return xor(or(shR(x, 2), shL(x, 30)), or(shR(x, 13), shL(x, 19)), or(shR(x, 22), shL(x, 10)));
        }

        int Sigma0(int x) {
            return (x >> 2 | x << 30) ^ (x >> 13 | x << 19) ^ (x >> 22 | x << 10);
        }

        IntVector Sigma1(IntVector x) {
            return xor(or(shR(x, 6), shL(x, 26)), or(shR(x, 11), shL(x, 21)), or(shR(x, 25), shL(x, 7)));
        }

        int Sigma1(int x) {
            return (x >> 6 | x << 26) ^ (x >> 11 | x << 21) ^ (x >> 25 | x << 7);
        }

        IntVector sigma0(IntVector x) {
            return xor(or(shR(x, 7), shL(x, 25)), or(shR(x, 18), shL(x, 14)), shR(x, 3));
        }

        int sigma0(int x) {
            return (x >> 7 | x << 25) ^ (x >> 18 | x << 14) ^ (x >> 3);
        }

        IntVector sigma1(IntVector x) {
            return xor(or(shR(x, 17), shL(x, 15)), or(shR(x, 19), shL(x, 13)), shR(x, 10));
        }

        int sigma1(int x) {
            return (x >> 17 | x << 15) ^ (x >> 19 | x << 13) ^ (x >> 10);
        }

        int bytesToIntLE(byte[] in, int offset) {
            return (int) LE.INT_ARRAY.get(in, offset);
        }

        int bytesToIntBE(byte[] in, int offset) {
            return (int) BE.INT_ARRAY.get(in, offset);
        }

        byte[] intToBytesLE(int value) {
            byte[] out = new byte[4];
            LE.INT_ARRAY.set(out, 0, value);
            return out;
        }

        public static byte[] intToBytesBE(int value) {
            byte[] out = new byte[4];
            BE.INT_ARRAY.set(out, 0, value);
            return out;
        }

        IntVector read2(byte[] chunk, int offset) {
            IntVector ret = IntVector.fromArray(SPECIES_64, new int[] {
                    bytesToIntLE(chunk, 0 + offset),
                    bytesToIntLE(chunk, 32 + offset)
            }, 0);
            return ret;
        }

        IntVector read4(byte[] chunk, int offset) {
            IntVector ret = IntVector.fromArray(SPECIES_128, new int[] {
                bytesToIntLE(chunk, 0 + offset),
                    bytesToIntLE(chunk, 64 + offset),
                    bytesToIntLE(chunk, 128 + offset),
                    bytesToIntLE(chunk, 192 + offset)
            }, 0);
            var shuffle = VectorShuffle.fromArray(SPECIES_128, new int[]{
                    12,13,14,15,   8, 9,10,11,
                    4, 5, 6, 7,    0, 1, 2, 3
            }, 0);
            ret.rearrange(shuffle, shuffle.laneIsValid());
            return ret;
        }

        IntVector read8(byte[] chunk, int offset) {
            System.out.println("read8, offset = " + offset);
            IntVector ret = IntVector.fromArray(SPECIES_256, new int[] {
                    bytesToIntLE(chunk, 0 + offset),
                    bytesToIntLE(chunk, 64 + offset),
                    bytesToIntLE(chunk, 128 + offset),
                    bytesToIntLE(chunk, 192 + offset),
                    bytesToIntLE(chunk, 256 + offset),
                    bytesToIntLE(chunk, 320 + offset),
                    bytesToIntLE(chunk, 384 + offset),
                    bytesToIntLE(chunk, 448 + offset)}, 0);
            System.out.println("read8 in: " + bytesToIntLE(chunk, 0 + offset) + ", " + bytesToIntLE(chunk, 64 + offset) +
                    ", " + bytesToIntLE(chunk, 128 + offset) + ", " + bytesToIntLE(chunk, 192 + offset) + ", " +
                    bytesToIntLE(chunk, 256 + offset) + ", " + bytesToIntLE(chunk, 320 + offset) + ", " +
                    bytesToIntLE(chunk, 384 + offset) + ", " + bytesToIntLE(chunk, 448 + offset));
            var shuffle = VectorShuffle.fromArray(ByteVector.SPECIES_256, new int[]{
                    12,13,14,15,   8, 9,10,11,
                    4, 5, 6, 7,    0, 1, 2, 3,
                    12,13,14,15,   8, 9,10,11,
                    4, 5, 6, 7,    0, 1, 2, 3 }, 0);
            ByteVector shuffled = ret.reinterpretAsBytes().rearrange(shuffle, shuffle.laneIsValid());
            System.out.println("read8 after shuffle: " + IntVector.fromByteArray(SPECIES_256, shuffled.toArray(), 0, ByteOrder.BIG_ENDIAN));
            return IntVector.fromByteArray(SPECIES_256, shuffled.toArray(), 0, ByteOrder.BIG_ENDIAN);
        }

        void write4(byte[] out, int offset, IntVector v) {
            var shuffle = VectorShuffle.fromArray(SPECIES_128, new int[]{
                    12,13,14,15,   8, 9,10,11,
                    4, 5, 6, 7,    0, 1, 2, 3}, 0);
            System.arraycopy(intToBytesLE(v.lane(3)), 0, out, 0 + offset, 4);
            System.arraycopy(intToBytesLE(v.lane(2)), 0, out, 32 + offset, 4);
            System.arraycopy(intToBytesLE(v.lane(1)), 0, out, 64 + offset, 4);
            System.arraycopy(intToBytesLE(v.lane(0)), 0, out, 96 + offset, 4);
            System.out.println("out: " + Arrays.toString(out));
        }

        void write8(byte[] out, int offset, IntVector v) {
            System.out.println("write8, offset: " + offset);
            var shuffle = VectorShuffle.fromArray(ByteVector.SPECIES_256, new int[]{
                    12,13,14,15,   8, 9,10,11,
                    4, 5, 6, 7,    0, 1, 2, 3,
                    12,13,14,15,   8, 9,10,11,
                    4, 5, 6, 7,    0, 1, 2, 3 }, 0);
            ByteVector shuffled = v.reinterpretAsBytes().rearrange(shuffle, shuffle.laneIsValid());
            IntVector shuffledInt = IntVector.fromByteArray(SPECIES_256, shuffled.toArray(), 0, ByteOrder.BIG_ENDIAN);
            System.out.println("shuffledInt: " + shuffledInt);
            System.out.println("Writing byte in last open position: " + bytesToHex(intToBytesLE(shuffledInt.lane(7))));
            System.arraycopy(intToBytesLE(shuffledInt.lane(0)), 0, out, 0 + offset, 4);
            System.arraycopy(intToBytesLE(shuffledInt.lane(1)), 0, out, 32 + offset, 4);
            System.arraycopy(intToBytesLE(shuffledInt.lane(2)), 0, out, 64 + offset, 4);
            System.arraycopy(intToBytesLE(shuffledInt.lane(3)), 0, out, 96 + offset, 4);
            System.arraycopy(intToBytesLE(shuffledInt.lane(4)), 0, out, 128 + offset, 4);
            System.arraycopy(intToBytesLE(shuffledInt.lane(5)), 0, out, 160 + offset, 4);
            System.arraycopy(intToBytesLE(shuffledInt.lane(6)), 0, out, 192 + offset, 4);
            System.arraycopy(intToBytesLE(shuffledInt.lane(7)), 0, out, 224 + offset, 4);
            System.out.println("out: " + bytesToHex(out));
        }

        /**
         * Takes a 64-byte chunk.
         * @param in
         */
        private void transform(byte[] in) {
            System.out.println("one-way transform, in = " + bytesToHex(in));
            int a = H[0];
            int b = H[1];
            int c = H[2];
            int d = H[3];
            int e = H[4];
            int f = H[5];
            int g = H[6];
            int h = H[7];
            System.out.println("a = " + a);
            System.out.println("b = " + b);
            System.out.println("c = " + c);
            System.out.println("d = " + d);
            System.out.println("e = " + e);
            System.out.println("f = " + f);
            System.out.println("g = " + g);
            System.out.println("h = " + h);

            int w0 = bytesToIntBE(in, 0);
            int t1 = h + Sigma1(e) + ch(e, f, g) + 0x428a2f98 + w0;
            int t2= Sigma0(a) + maj(a, b, c);
            d = d + t1;
            h = t1 + t2;

            int w1 = bytesToIntBE(in, 4);
            t1 = g + Sigma1(d) + ch(d, e, f) + 0x71374491 + w1;
            t2 = Sigma0(h) + maj(h, a, b);
            c = c + t1;
            g = t1 + t2;

            int w2 = bytesToIntBE(in, 8);
            t1 = f + Sigma1(c) + ch(c, d, e) + 0xb5c0fbcf + w2;
            t2 = Sigma0(g) + maj(g, h, a);
            b = b + t1;
            f = t1 + t2;

            int w3 = bytesToIntBE(in, 12);
            t1 = e + Sigma1(b) + ch(b, c, d) + 0xe9b5dba5 + w3;
            t2 = Sigma0(f) + maj(f, g, h);
            a = a + t1;
            e = t1 + t2;

            int w4 = bytesToIntBE(in, 16);
            t1 = d + Sigma1(a) + ch(a, b, c) + 0x3956c25b + w4;
            t2 = Sigma0(e) + maj(e, f, g);
            h = h + t1;
            d = t1 + t2;

            int w5 = bytesToIntBE(in, 20);
            t1 = c + Sigma1(h) + ch(h, a, b) + 0x59f111f1 + w5;
            t2 = Sigma0(d) + maj(d, e, f);
            g = g + t1;
            c = t1 + t2;

            int w6 = bytesToIntBE(in, 24);
            t1 = b + Sigma1(g) + ch(g, h, a) + 0x923f82a4 + w6;
            t2 = Sigma0(c) + maj(c, d, e);
            f = f + t1;
            b = t1 + t2;

            int w7 = bytesToIntBE(in, 28);
            t1 = a + Sigma1(f) + ch(f, g, h) + 0xab1c5ed5 + w7;
            t2 = Sigma0(b) + maj(b, c, d);
            e = e + t1;
            a = t1 + t2;

            int w8 = bytesToIntBE(in, 32);
            t1 = h + Sigma1(e) + ch(e, f, g) + 0xd807aa98 + w8;
            t2 = Sigma0(a) + maj(a, b, c);
            d = d + t1;
            h = t1 + t2;

            int w9 = bytesToIntBE(in, 36);
            t1 = g + Sigma1(d) + ch(d, e, f) + 0x12835b01 + w9;
            t2 = Sigma0(h) + maj(h, a, b);
            c = c + t1;
            b = t1 + t2;

            int w10 = bytesToIntBE(in, 40);
            t1 = f + Sigma1(c) + ch(c, d, e) + 0x243185be + w10;
            t2 = Sigma0(g) + maj(g, h, a);
            b = b + t1;
            f = t1 + t2;

            int w11 = bytesToIntBE(in, 44);
            t1 = e + Sigma1(b) + ch(b, c, d) + 0x550c7dc3 + w11;
            t2 = Sigma0(f) + maj(f, g, h);
            a = a + t1;
            e = t1 + t2;

            int w12 = bytesToIntBE(in, 48);
            t1 = d + Sigma1(a) + ch(a, b, c) + 0x72be5d74 + w12;
            t2 = Sigma0(e) + maj(e, f, g);
            h = h + t1;
            d = t1 + t2;

            int w13 = bytesToIntBE(in, 52);
            t1 = c + Sigma1(h) + ch(h, a, b) + 0x80deb1fe + w13;
            t2 = Sigma0(d) + maj(d, e, f);
            g = g + t1;
            c = t1 + t2;

            int w14 = bytesToIntBE(in, 56);
            t1 = b + Sigma1(g) + ch(g, h, a) + 0x9bdc06a7 + w14;
            t2 = Sigma0(c) + maj(c, d, e);
            f = f + t1;
            b = t1 + t2;

            int w15 = bytesToIntBE(in, 60);
            t1 = a + Sigma1(f) + ch(f, g, h) + 0xc19bf174 + w15;
            t2 = Sigma0(b) + maj(b, c, d);
            e = e + t1;
            a = t1 + t2;

            t1 = h + Sigma1(e) + ch(e, f, g) + 0xe49b69c1 + (w0 += sigma1(w14) + w9 + sigma0(w1));
            t2 = Sigma0(a) + maj(a, b, c);
            d = d + t1;
            h = t1 + t2;

            t1 = c + Sigma1(d) + ch(d, e, f) + 0xefbe4786 + (w1 += sigma1(w15) + w10 + sigma0(w2));
            t2 = Sigma0(h) + maj(h, a, b);
            c = c + t1;
            g = t1 + t2;

            t1 = f + Sigma1(c) + ch(c, d, e) + 0x0fc19dc6 + (w2 += sigma1(w0) + w11 + sigma0(w3));
            t2 = Sigma0(g) + maj(g, h, a);
            b = b + t1;
            f = t1 + t2;

            t1 = e + Sigma1(b) + ch(b, c, d) + 0x240ca1cc + (w3 += sigma1(w1) + w12 + sigma0(w4));
            t2 = Sigma0(f) + maj(f, g, h);
            a = a + t1;
            e = t1 + t2;

            t1 = d + Sigma1(a) + ch(a, b, c) + 0x2de92c6f + (w4 += sigma1(w2) + w13 + sigma0(w5));
            t2 = Sigma0(e) + maj(e, f, g);
            h = h + t1;
            d = t1 + t2;

            t1 = c + Sigma1(h) + ch(h, a, b) + 0x4a7484aa + (w5 += sigma1(w3) + w14 + sigma0(w6));
            t2 = Sigma0(d) + maj(d, e, f);
            g = g + t1;
            c = t1 + t2;

            t1 = b + Sigma1(g) + ch(g, h, a) + 0x5cb0a9dc + (w6 += sigma1(w4) + w15 + sigma0(w7));
            t2 = Sigma0(c) + maj(c, d, e);
            f = f + t1;
            b = t1 + t2;

            t1 = a + Sigma1(f) + ch(f, g, h) + 0x76f988da + (w7 += sigma1(w5) + w0 + sigma0(w8));
            t2 = Sigma0(b) + maj(b, c, d);
            e = e + t1;
            a = t1 + t2;

            t1 = h + Sigma1(e) + ch(e, f, g) + 0x983e5152 + (w8 += sigma1(w6) + w1 + sigma0(w9));
            t2= Sigma0(a) + maj(a, b, c);
            d = d + t1;
            h = t1 + t2;

            t1 = g + Sigma1(d) + ch(d, e, f) + 0xa831c66d + (w9 += sigma1(w7) + w2 + sigma0(w10));
            t2 = Sigma0(h) + maj(h, a, b);
            c = c + t1;
            g = t1 + t2;

            t1 = f + Sigma1(c) + ch(c, d, e) + 0xb00327c8 + (w10 += sigma1(w8) + w3 + sigma0(w11));
            t2 = Sigma0(g) + maj(g, h, a);
            b = b + t1;
            f = t1 + t2;

            t1 = e + Sigma1(b) + ch(b, c, d) + 0xbf597fc7 + (w11 += sigma1(w9) + w4 + sigma0(w12));
            t2 = Sigma0(f) + maj(f, g, h);
            a = a + t1;
            e = t1 + t2;

            t1 = d + Sigma1(a) + ch(a, b, c) + 0xc6e00bf3 + (w12 += sigma1(w10) + w5 + sigma0(w13));
            t2 = Sigma0(e) + maj(e, f, g);
            h = h + t1;
            d = t1 + t2;

            t1 = c + Sigma1(h) + ch(h, a, b) + 0xd5a79147 + (w13 += sigma1(w11) + w6 + sigma0(w14));
            t2 = Sigma0(d) + maj(d, e, f);
            g = g + t1;
            c = t1 + t2;

            t1 = b + Sigma1(g) + ch(g, h, a) + 0x06ca6351 + (w14 += sigma1(w12) + w7 + sigma0(w15));
            t2 = Sigma0(c) + maj(c, d, e);
            f = f + t1;
            b = t1 + t2;

            t1 = a + Sigma1(f) + ch(f, g, h) + 0x14292967 + (w15 += sigma1(w13) + w8 + sigma0(w0));
            t2 = Sigma0(b) + maj(b, c, d);
            e = e + t1;
            a = t1 + t2;

            t1 = h + Sigma1(e) + ch(e, f, g) + 0x27b70a85 + (w0 += sigma1(w14) + w9 + sigma0(w1));
            t2 = Sigma0(a) + maj(a, b, c);
            d = d + t1;
            h = t1 + t2;

            t1 = g + Sigma1(d) + ch(d, e, f) + 0x2e1b2138 + (w1 += sigma1(w15) + w10 + sigma0(w2));
            t2 = Sigma0(h) + maj(h, a, b);
            c = c + t1;
            g = t1 + t2;

            t1 = f + Sigma1(c) + ch(c, d, e) + 0x4d2c6dfc + (w2 += sigma1(w0) + w11 + sigma0(w3));
            t2 = Sigma0(g) + maj(g, h, a);
            b = b + t1;
            f = t1 + t2;

            t1 = e + Sigma1(b) + ch(b, c, d) + 0x53380d13 + (w3 += sigma1(w1) + w12 + sigma0(w4));
            t2 = Sigma0(f) + maj(f, g, h);
            a = a + t1;
            e = t1 + t2;

            t1 = d + Sigma1(a) + ch(a, b, c) + 0x650a7354 + (w4 += sigma1(w2) + w13 + sigma0(w5));
            t2 = Sigma0(e) + maj(e, f, g);
            h = h + t1;
            d = t1 + t2;

            t1 = c + Sigma1(h) + ch(h, a, b) + 0x766a0abb + (w5 += sigma1(w3) + w14 + sigma0(w6));
            t2 = Sigma0(d) + maj(d, e, f);
            g = g + t1;
            c = t1 + t2;

            t1 = b + Sigma1(g) + ch(g, h, a) + 0x81c2c92e + (w6 += sigma1(w4) + w15 + sigma0(w7));
            t2 = Sigma0(c) + maj(c, d, e);
            f = f + t1;
            b = t1 + t2;

            t1 = a + Sigma1(f) + ch(f, g, h) + 0x92722c85 + (w7 += sigma1(w5) + w0 + sigma0(w8));
            t2 = Sigma0(b) + maj(b, c, d);
            e = e + t1;
            a = t1 + t2;

            t1 = h + Sigma1(e) + ch(e, f, g) + 0xa2bfe8a1 + (w8 += sigma1(w6) + w1 + sigma0(w9));
            t2 = Sigma0(a) + maj(a, b, c);
            d = d + t1;
            h = t1 + t2;

            t1 = g + Sigma1(d) + ch(d, e, f) + 0xa81a664b + (w9 += sigma1(w7) + w2 + sigma0(w10));
            t2 = Sigma0(h) + maj(h, a, b);
            c = c + t1;
            g = t1 + t2;

            t1 = f + Sigma1(c) + ch(c, d, e) + 0xc24b8b70 + (w10 += sigma1(w8) + w3 + sigma0(w11));
            t2 = Sigma0(g) + maj(g, h, a);
            b = b + t1;
            f = t1 + t2;

            t1 = e + Sigma1(b) + ch(b, c, d) + 0xc76c51a3 + (w11 += sigma1(w9) + w4 + sigma0(w12));
            t2 = Sigma0(f) + maj(f, g, h);
            a = a + t1;
            e = t1 + t2;

            t1 = d + Sigma1(a) + ch(a, b, c) + 0xd192e819 + (w12 += sigma1(w10) + w5 + sigma0(w13));
            t2 = Sigma0(e) + maj(e, f, g);
            h = h + t1;
            d = t1 + t2;

            t1 = c + Sigma1(h) + ch(h, a, b) + 0xd6990624 + (w13 += sigma1(w11) + w6 + sigma0(w14));
            t2 = Sigma0(d) + maj(d, e, f);
            g = g + t1;
            c = t1 + t2;

            t1 = b + Sigma1(g) + ch(g, h, a) + 0xf40e3585 + (w14 += sigma1(w12) + w7 + sigma0(w15));
            t2 = Sigma0(c) + maj(c, d, e);
            f = f + t1;
            b = t1 + t2;

            t1 = a + Sigma1(f) + ch(f, g, h) + 0x106aa070 + (w15 += sigma1(w13) + w8 + sigma0(w0));
            t2 = Sigma0(b) + maj(b, c, d);
            e = e + t1;
            a = t1 + t2;

            t1 = h + Sigma1(e) + ch(e, f, g) + 0x19a4c116 + (w0 += sigma1(w14) + w9 + sigma0(w1));
            t2 = Sigma0(a) + maj(a, b, c);
            d = d + t1;
            h = t1 + t2;

            t1 = g + Sigma1(d) + ch(d, e, f) + 0x1e376c08 + (w1 += sigma1(w15) + w10 + sigma0(w2));
            t2 = Sigma0(h) + maj(h, a, b);
            c = c + t1;
            g = t1 + t2;

            t1 = f + Sigma1(c) + ch(c, d, e) + 0x2748774c + (w2 += sigma1(w0) + w11 + sigma0(w3));
            t2 = Sigma0(g) + maj(g, h, a);
            b = b + t1;
            f = t1 + t2;

            t1 = e + Sigma1(b) + ch(b, c, d) + 0x34b0bcb5 + (w3 += sigma1(w1) + w12 + sigma0(w4));
            t2 = Sigma0(f) + maj(f, g, h);
            a = a + t1;
            e = t1 + t2;

            t1 = d + Sigma1(a) + ch(a, b, c) + 0x391c0cb3 + (w4 += sigma1(w2) + w13 + sigma0(w5));
            t2 = Sigma0(e) + maj(e, f, g);
            h = h + t1;
            d = t1 + t2;

            t1 = c + Sigma1(h) + ch(h, a, b) + 0x4ed8aa4a + (w5 += sigma1(w3) + w14 + sigma0(w6));
            t2 = Sigma0(d) + maj(d, e, f);
            g = g + t1;
            c = t1 + t2;

            t1 = b + Sigma1(g) + ch(g, h, a) + 0x5b9cca4f + (w6 += sigma1(w4) + w15 + sigma0(w7));
            t2 = Sigma0(c) + maj(c, d, e);
            f = f + t1;
            b = t1 + t2;

            t1 = a + Sigma1(f) + ch(f, g, h) + 0x682e6ff3 + (w7 += sigma1(w5) + w0 + sigma0(w8));
            t2 = Sigma0(b) + maj(b, c, d);
            e = e + t1;
            a = t1 + t2;

            t1 = h + Sigma1(e) + ch(e, f, g) + 0x748f82ee + (w8 += sigma1(w6) + w1 + sigma0(w9));
            t2 = Sigma0(a) + maj(a, b, c);
            d = d + t1;
            h = t1 + t2;

            t1 = g + Sigma1(d) + ch(d, e, f) + 0x78a5636f + (w9 += sigma1(w7) + w2 + sigma0(w10));
            t2 = Sigma0(h) + maj(h, a, b);
            c = c + t1;
            g = t1 + t2;

            t1 = f + Sigma1(c) + ch(c, d, e) + 0x84c87814 + (w10 += sigma1(w8) + w3 + sigma0(w11));
            t2 = Sigma0(g) + maj(g, h, a);
            b = b + t1;
            f = t1 + t2;

            t1 = e + Sigma1(b) + ch(b, c, d) + 0x8cc70208 + (w11 += sigma1(w9) + w4 + sigma0(w12));
            t2 = Sigma0(f) + maj(f, g, h);
            a = a + t1;
            e = t1 + t2;

            t1 = d + Sigma1(a) + ch(a, b, c) + 0x90befffa + (w12 += sigma1(w10) + w5 + sigma0(w13));
            t2 = Sigma0(e) + maj(e, f, g);
            h = h + t1;
            d = t1 + t2;

            t1 = c + Sigma1(h) + ch(h, a, b) + 0xa4506ceb + (w13 += sigma1(w11) + w6 + sigma0(w14));
            t2 = Sigma0(d) + maj(d, e, f);
            g = g + t1;
            c = t1 + t2;

            t1 = b + Sigma1(g) + ch(g, h, a) + 0xbef9a3f7 + (w14 + sigma1(w12) + w7 + sigma0(w15));
            t2 = Sigma0(c) + maj(c, d, e);
            f = f + t1;
            b = t1 + t2;

            t1 = a + Sigma1(f) + ch(f, g, h) + 0xc67178f2 + (w15 + sigma1(w13) + w8 + sigma0(w0));
            t2 = Sigma0(b) + maj(b, c, d);
            e = e + t1;
            a = t1 + t2;

            H[0] += a;
            H[1] += b;
            H[2] += c;
            H[3] += d;
            H[4] += e;
            H[5] += f;
            H[6] += g;
            H[7] += h;
            System.out.println("H[0] = " + bytesToHex(intToBytesBE(H[0])));
            System.out.println("H[1] = " + bytesToHex(intToBytesBE(H[1])));
            System.out.println("H[2] = " + bytesToHex(intToBytesBE(H[2])));
            System.out.println("H[3] = " + bytesToHex(intToBytesBE(H[3])));
            System.out.println("H[4] = " + bytesToHex(intToBytesBE(H[4])));
            System.out.println("H[5] = " + bytesToHex(intToBytesBE(H[5])));
            System.out.println("H[6] = " + bytesToHex(intToBytesBE(H[6])));
            System.out.println("H[7] = " + bytesToHex(intToBytesBE(H[7])));
        }

        /**
         * Takes n-byte chunks corresponding to 8way (256-bit vectors), 4way (128-bit vectors) and 2way (64-bit vectors).
         *
         * 8way = 512 bytes
         * 4way = 256 bytes
         * 2way = 128 bytes
         * 1way = 64 bytes
         *
         * @param in
         * @return
         */
        public void transform_multi_way(byte[] in, VectorSpecies<Integer> species, BiFunction<byte[], Integer, IntVector> readFunc) {
            System.out.println("transform_multi_way:\n");
            System.out.println("in: " + bytesToHex(in));

            IntVector aVec = IntVector.broadcast(species, H[0]);
            IntVector bVec = IntVector.broadcast(species, H[1]);
            IntVector cVec = IntVector.broadcast(species, H[2]);
            IntVector dVec = IntVector.broadcast(species, H[3]);
            IntVector eVec = IntVector.broadcast(species, H[4]);
            IntVector fVec = IntVector.broadcast(species, H[5]);
            IntVector gVec = IntVector.broadcast(species, H[6]);
            IntVector hVec = IntVector.broadcast(species, H[7]);

            IntVector w0 = readFunc.apply(in, 0);
            IntVector t1 = add(hVec, Sigma1(eVec), ch(eVec, fVec, gVec), add(IntVector.broadcast(species, 0x428a2f98), w0));
            IntVector t2 = add(Sigma0(aVec), maj(aVec, bVec, cVec));
            System.out.println("After round 0");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            dVec = add(dVec, t1);
            hVec = add(t1, t2);

            IntVector w1 = readFunc.apply(in, 4);
            t1 = add(gVec, Sigma1(dVec), ch(dVec, eVec, fVec), add(IntVector.broadcast(species, 0x71374491), w1));
            t2 = add(Sigma0(hVec), maj(hVec, aVec, bVec));
            System.out.println("After round 1");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            cVec = add(cVec, t1);
            gVec = add(t1, t2);

            IntVector w2 = readFunc.apply(in, 8);
            t1= add(fVec, Sigma1(cVec), ch(cVec, dVec, eVec), add(IntVector.broadcast(species, 0xb5c0fbcf), w2));
            t2 = add(Sigma0(gVec), maj(gVec, hVec, aVec));
            System.out.println("After round 2");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            bVec = add(bVec, t1);
            fVec = add(t1, t2);

            IntVector w3 = readFunc.apply(in, 12);
            t1 = add(eVec, Sigma1(bVec), ch(bVec, cVec, dVec), add(IntVector.broadcast(species, 0xe9b5dba5), w3));
            t2 = add(Sigma0(fVec), maj(fVec, gVec, hVec));
            System.out.println("After round 3");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            aVec = add(aVec, t1);
            eVec = add(t1, t2);

            IntVector w4 = readFunc.apply(in, 16);
            t1 = add(dVec, Sigma1(aVec), ch(aVec, bVec, cVec), add(IntVector.broadcast(species, 0x3956c25b), w4));
            t2 = add(Sigma0(eVec), maj(eVec, fVec, gVec));
            System.out.println("After round 4");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            hVec = add(hVec, t1);
            dVec = add(t1, t2);

            IntVector w5 = readFunc.apply(in, 20);
            t1 = add(cVec, Sigma1(hVec), ch(hVec, aVec, bVec), add(IntVector.broadcast(species, 0x59f111f1), w5));
            t2 = add(Sigma0(dVec), maj(dVec, eVec, fVec));
            System.out.println("After round 5");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            gVec = add(gVec, t1);
            cVec = add(t1, t2);

            IntVector w6 = readFunc.apply(in, 24);
            t1 = add(bVec, Sigma1(gVec), ch(gVec, hVec, aVec), add(IntVector.broadcast(species, 0x923f82a4), w6));
            t2 = add(Sigma0(cVec), maj(cVec, dVec, eVec));
            System.out.println("After round 6");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            fVec = add(fVec, t1);
            bVec = add(t1, t2);

            IntVector w7 = readFunc.apply(in, 28);
            t1 = add(aVec, Sigma1(fVec), ch(fVec, gVec, hVec), add(IntVector.broadcast(species, 0xab1c5ed5), w7));
            t2 = add(Sigma0(bVec), maj(bVec, cVec, dVec));
            System.out.println("After round 7");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            eVec = add(eVec, t1);
            aVec = add(t1, t2);

            IntVector w8 = readFunc.apply(in, 32);
            t1 = add(hVec, Sigma1(eVec), ch(eVec, fVec, gVec), add(IntVector.broadcast(species, 0xd807aa98), w8));
            t2 = add(Sigma0(aVec), maj(aVec, bVec, cVec));
            System.out.println("After round 8");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            dVec = add(dVec, t1);
            hVec = add(t1, t2);

            IntVector w9 = readFunc.apply(in, 36);
            t1 = add(gVec, Sigma1(dVec), ch(dVec, eVec, fVec), add(IntVector.broadcast(species, 0x12835b01), w9));
            t2 = add(Sigma0(hVec), maj(hVec, aVec, bVec));
            System.out.println("After round 9");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            cVec = add(cVec, t1);
            gVec = add(t1, t2);

            IntVector w10 = readFunc.apply(in, 40);
            t1 = add(fVec, Sigma1(cVec), ch(cVec, dVec, eVec), add(IntVector.broadcast(species, 0x243185be), w10));
            t2 = add(Sigma0(gVec), maj(gVec, hVec, aVec));
            System.out.println("After round 10");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            bVec = add(bVec, t1);
            fVec = add(t1, t2);

            IntVector w11 = readFunc.apply(in, 44);
            t1 = add(eVec, Sigma1(bVec), ch(bVec, cVec, dVec), add(IntVector.broadcast(species, 0x550c7dc3), w11));
            t2 = add(Sigma0(fVec), maj(fVec, gVec, hVec));
            System.out.println("After round 11");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            aVec = add(aVec, t1);
            eVec = add(t1, t2);

            IntVector w12 = readFunc.apply(in, 48);
            t1 = add(dVec, Sigma1(aVec), ch(aVec, bVec, cVec), add(IntVector.broadcast(species, 0x72be5d74), w12));
            t2 = add(Sigma0(eVec), maj(eVec, fVec, gVec));
            System.out.println("After round 12");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            hVec = add(hVec, t1);
            dVec = add(t1, t2);

            IntVector w13 = readFunc.apply(in, 52);
            t1 = add(cVec, Sigma1(hVec), ch(hVec, aVec, bVec), add(IntVector.broadcast(species, 0x80deb1fe), w13));
            t2 = add(Sigma0(dVec), maj(dVec, eVec, fVec));
            System.out.println("After round 13");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            gVec = add(gVec, t1);
            cVec = add(t1, t2);

            IntVector w14 = readFunc.apply(in, 56);
            t1 = add(bVec, Sigma1(gVec), ch(gVec, hVec, aVec), add(IntVector.broadcast(species, 0x9bdc06a7), w14));
            t2 = add(Sigma0(cVec), maj(cVec, dVec, eVec));
            System.out.println("After round 14");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            fVec = add(fVec, t1);
            bVec = add(t1, t2);

            IntVector w15 = readFunc.apply(in, 60);
            t1 = add(aVec, Sigma1(fVec), ch(fVec, gVec, hVec), add(IntVector.broadcast(species, 0xc19bf174), w15));
            t2 = add(Sigma0(bVec), maj(bVec, cVec, dVec));
            System.out.println("After round 15");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            eVec = add(eVec, t1);
            aVec = add(t1, t2);

            t1 = add(hVec, Sigma1(eVec), ch(eVec, fVec, gVec), add(IntVector.broadcast(species, 0xe49b69c1), w0 = inc(w0, sigma1(w14), w9, sigma0(w1))));
            t2 = add(Sigma0(aVec), maj(aVec, bVec, cVec));
            System.out.println("After round 16");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            dVec = add(dVec, t1);
            hVec = add(t1, t2);

            t1 = add(gVec, Sigma1(dVec), ch(dVec, eVec, fVec), add(IntVector.broadcast(species, 0xefbe4786), w1 = inc(w1, sigma1(w15), w10, sigma0(w2))));
            t2 = add(Sigma0(hVec), maj(hVec, aVec, bVec));
            System.out.println("After round 17");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            cVec = add(cVec, t1);
            gVec = add(t1, t2);

            t1 = add(fVec, Sigma1(cVec), ch(cVec, dVec, eVec), add(IntVector.broadcast(species, 0x0fc19dc6), w2 = inc(w2, sigma1(w0), w11, sigma0(w3))));
            t2 = add(Sigma0(gVec), maj(gVec, hVec, aVec));
            System.out.println("After round 18");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            bVec = add(bVec, t1);
            fVec = add(t1, t2);

            t1 = add(eVec, Sigma1(bVec), ch(bVec, cVec, dVec), add(IntVector.broadcast(species, 0x240ca1cc), w3 = inc(w3, sigma1(w1), w12, sigma0(w4))));
            t2 = add(Sigma0(fVec), maj(fVec, gVec, hVec));
            System.out.println("After round 19");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            aVec = add(aVec, t1);
            eVec = add(t1, t2);

            t1 = add(dVec, Sigma1(aVec), ch(aVec, bVec, cVec), add(IntVector.broadcast(species, 0x2de92c6f), w4 = inc(w4, sigma1(w2), w13, sigma0(w5))));
            t2 = add(Sigma0(eVec), maj(eVec, fVec, gVec));
            System.out.println("After round 20");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            hVec = add(hVec, t1);
            dVec = add(t1, t2);

            t1 = add(cVec, Sigma1(hVec), ch(hVec, aVec, bVec), add(IntVector.broadcast(species, 0x4a7484aa), w5 = inc(w5, sigma1(w3), w14, sigma0(w6))));
            t2 = add(Sigma0(dVec), maj(dVec, eVec, fVec));
            System.out.println("After round 22");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            gVec = add(gVec, t1);
            cVec = add(t1, t2);

            t1 = add(bVec, Sigma1(gVec), ch(gVec, hVec, aVec), add(IntVector.broadcast(species, 0x5cb0a9dc), w6 = inc(w6, sigma1(w4), w15, sigma0(w7))));
            t2 = add(Sigma0(cVec), maj(cVec, dVec, eVec));
            System.out.println("After round 23");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            fVec = add(fVec, t1);
            bVec = add(t1, t2);

            t1 = add(aVec, Sigma1(fVec), ch(fVec, gVec, hVec), add(IntVector.broadcast(species, 0x76f988da), w7 = inc(w7, sigma1(w5), w0, sigma0(w8))));
            t2 = add(Sigma0(bVec), maj(bVec, cVec, dVec));
            System.out.println("After round 24");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            eVec = add(eVec, t1);
            aVec = add(t1, t2);

            t1 = add(hVec, Sigma1(eVec), ch(eVec, fVec, gVec), add(IntVector.broadcast(species, 0x983e5152), w8 = inc(w8, sigma1(w6), w1, sigma0(w9))));
            t2 = add(Sigma0(aVec), maj(aVec, bVec, cVec));
            System.out.println("After round 25");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            dVec = add(dVec, t1);
            hVec = add(t1, t2);

            t1 = add(gVec, Sigma1(dVec), ch(dVec, eVec, fVec), add(IntVector.broadcast(species, 0xa831c66d), w9 = inc(w9, sigma1(w7), w2, sigma0(w10))));
            t2 = add(Sigma0(hVec), maj(hVec, aVec, bVec));
            System.out.println("After round 26");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            cVec = add(cVec, t1);
            gVec = add(t1, t2);

            t1 = add(fVec, Sigma1(cVec), ch(cVec, dVec, eVec), add(IntVector.broadcast(species, 0xb00327c8), w10 = inc(w10, sigma1(w8), w3, sigma0(w11))));
            t2 = add(Sigma0(gVec), maj(gVec, hVec, aVec));
            System.out.println("After round 27");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            bVec = add(bVec, t1);
            fVec = add(t1, t2);

            t1 = add(eVec, Sigma1(bVec), ch(bVec, cVec, dVec), add(IntVector.broadcast(species, 0xbf597fc7), w11 = inc(w11, sigma1(w9), w4, sigma0(w12))));
            t2 = add(Sigma0(fVec), maj(fVec, gVec, hVec));
            System.out.println("After round 28");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            aVec = add(aVec, t1);
            eVec = add(t1, t2);

            t1 = add(dVec, Sigma1(aVec), ch(aVec, bVec, cVec), add(IntVector.broadcast(species, 0xc6e00bf3), w12 = inc(w12, sigma1(w10), w5, sigma0(w13))));
            t2 = add(Sigma0(eVec), maj(eVec, fVec, gVec));
            System.out.println("After round 29");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            hVec = add(hVec, t1);
            dVec = add(t1, t2);

            t1 = add(cVec, Sigma1(hVec), ch(hVec, aVec, bVec), add(IntVector.broadcast(species, 0xd5a79147), w13 = inc(w13, sigma1(w11), w6, sigma0(w14))));
            t2 = add(Sigma0(dVec), maj(dVec, eVec, fVec));
            System.out.println("After round 30");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            gVec = add(gVec, t1);
            cVec = add(t1, t2);

            t1 = add(bVec, Sigma1(gVec), ch(gVec, hVec, aVec), add(IntVector.broadcast(species, 0x06ca6351), w14 = inc(w14, sigma1(w12), w7, sigma0(w15))));
            t2 = add(Sigma0(cVec), maj(cVec, dVec, eVec));
            System.out.println("After round 31");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            fVec = add(fVec, t1);
            bVec = add(t1, t2);

            t1 = add(aVec, Sigma1(fVec), ch(fVec, gVec, hVec), add(IntVector.broadcast(species, 0x14292967), w15 = inc(w15, sigma1(w13), w8, sigma0(w0))));
            t2 = add(Sigma0(bVec), maj(bVec, cVec, dVec));
            System.out.println("After round 32");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            eVec = add(eVec, t1);
            aVec = add(t1, t2);

            t1 = add(hVec, Sigma1(eVec), ch(eVec, fVec, gVec), add(IntVector.broadcast(species, 0x27b70a85), w0 = inc(w0, sigma1(w14), w9, sigma0(w1))));
            t2 = add(Sigma0(aVec), maj(aVec, bVec, cVec));
            System.out.println("After round 33");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            dVec = add(dVec, t1);
            hVec = add(t1, t2);

            t1 = add(gVec, Sigma1(dVec), ch(dVec, eVec, fVec), add(IntVector.broadcast(species, 0x2e1b2138), w1 = inc(w1, sigma1(w15), w10, sigma0(w2))));
            t2 = add(Sigma0(hVec), maj(hVec, aVec, bVec));
            System.out.println("After round 34");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            cVec = add(cVec, t1);
            gVec = add(t1, t2);

            t1 = add(fVec, Sigma1(cVec), ch(cVec, dVec, eVec), add(IntVector.broadcast(species, 0x4d2c6dfc), w2 = inc(w2, sigma1(w0), w11, sigma0(w3))));
            t2 = add(Sigma0(gVec), maj(gVec, hVec, aVec));
            System.out.println("After round 35");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            bVec = add(bVec, t1);
            fVec = add(t1, t2);

            t1 = add(eVec, Sigma1(bVec), ch(bVec, cVec, dVec), add(IntVector.broadcast(species, 0x53380d13), w3 = inc(w3, sigma1(w1), w12, sigma0(w4))));
            t2 = add(Sigma0(fVec), maj(fVec, gVec, hVec));
            System.out.println("After round 36");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            aVec = add(aVec, t1);
            eVec = add(t1, t2);

            t1 = add(dVec, Sigma1(aVec), ch(aVec, bVec, cVec), add(IntVector.broadcast(species, 0x650a7354), w4 = inc(w4, sigma1(w2), w13, sigma0(w5))));
            t2 = add(Sigma0(eVec), maj(eVec, fVec, gVec));
            System.out.println("After round 37");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            hVec = add(hVec, t1);
            dVec = add(t1, t2);

            t1 = add(cVec, Sigma1(hVec), ch(hVec, aVec, bVec), add(IntVector.broadcast(species, 0x766a0abb), w5 = inc(w5, sigma1(w3), w14, sigma0(w6))));
            t2 = add(Sigma0(dVec), maj(dVec, eVec, fVec));
            System.out.println("After round 38");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            gVec = add(gVec, t1);
            cVec = add(t1, t2);

            t1 = add(bVec, Sigma1(gVec), ch(gVec, hVec, aVec), add(IntVector.broadcast(species, 0x81c2c92e), w6 = inc(w6, sigma1(w4), w15, sigma0(w7))));
            t2 = add(Sigma0(cVec), maj(cVec, dVec, eVec));
            System.out.println("After round 39");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            fVec = add(fVec, t1);
            bVec = add(t1, t2);

            t1 = add(aVec, Sigma1(fVec), ch(fVec, gVec, hVec), add(IntVector.broadcast(species, 0x92722c85), w7 = inc(w7, sigma1(w5), w0, sigma0(w8))));
            t2 = add(Sigma0(bVec), maj(bVec, cVec, dVec));
            System.out.println("After round 40");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            eVec = add(eVec, t1);
            aVec = add(t1, t2);

            t1 = add(hVec, Sigma1(eVec), ch(eVec, fVec, gVec), add(IntVector.broadcast(species, 0xa2bfe8a1), w8 = inc(w8, sigma1(w6), w1, sigma0(w9))));
            t2 = add(Sigma0(aVec), maj(aVec, bVec, cVec));
            System.out.println("After round 41");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            dVec = add(dVec, t1);
            hVec = add(t1, t2);

            t1 = add(gVec, Sigma1(dVec), ch(dVec, eVec, fVec), add(IntVector.broadcast(species, 0xa81a664b), w9 = inc(w9, sigma1(w7), w2, sigma0(w10))));
            t2 = add(Sigma0(hVec), maj(hVec, aVec, bVec));
            System.out.println("After round 42");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            cVec = add(cVec, t1);
            gVec = add(t1, t2);

            t1 = add(fVec, Sigma1(cVec), ch(cVec, dVec, eVec), add(IntVector.broadcast(species, 0xc24b8b70), w10 = inc(w10, sigma1(w8), w3, sigma0(w11))));
            t2 = add(Sigma0(gVec), maj(gVec, hVec, aVec));
            System.out.println("After round 43");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            bVec = add(bVec, t1);
            fVec = add(t1, t2);

            t1 = add(eVec, Sigma1(bVec), ch(bVec, cVec, dVec), add(IntVector.broadcast(species, 0xc76c51a3), w11 = inc(w11, sigma1(w9), w4, sigma0(w12))));
            t2 = add(Sigma0(fVec), maj(fVec, gVec, hVec));
            System.out.println("After round 44");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            aVec = add(aVec, t1);
            eVec = add(t1, t2);

            t1 = add(dVec, Sigma1(aVec), ch(aVec, bVec, cVec), add(IntVector.broadcast(species, 0xd192e819), w12 = inc(w12, sigma1(w10), w5, sigma0(w13))));
            t2 = add(Sigma0(eVec), maj(eVec, fVec, gVec));
            System.out.println("After round 45");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            hVec = add(hVec, t1);
            dVec = add(t1, t2);

            t1 = add(cVec, Sigma1(hVec), ch(hVec, aVec, bVec), add(IntVector.broadcast(species, 0xd6990624), w13 = inc(w13, sigma1(w11), w6, sigma0(w14))));
            t2 = add(Sigma0(dVec), maj(dVec, eVec, fVec));
            System.out.println("After round 46");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            gVec = add(gVec, t1);
            cVec = add(t1, t2);

            t1 = add(bVec, Sigma1(gVec), ch(gVec, hVec, aVec), add(IntVector.broadcast(species, 0xf40e3585), w14 = inc(w14, sigma1(w12), w7, sigma0(w15))));
            t2 = add(Sigma0(cVec), maj(cVec, dVec, eVec));
            System.out.println("After round 47");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            fVec = add(fVec, t1);
            bVec = add(t1, t2);

            t1 = add(aVec, Sigma1(fVec), ch(fVec, gVec, hVec), add(IntVector.broadcast(species, 0x106aa070), w15 = inc(w15, sigma1(w13), w8, sigma0(w0))));
            t2 = add(Sigma0(bVec), maj(bVec, cVec, dVec));
            System.out.println("After round 48");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            eVec = add(eVec, t1);
            aVec = add(t1, t2);

            t1 = add(hVec, Sigma1(eVec), ch(eVec, fVec, gVec), add(IntVector.broadcast(species, 0x19a4c116), w0 = inc(w0, sigma1(w14), w9, sigma0(w1))));
            t2 = add(Sigma0(aVec), maj(aVec, bVec, cVec));
            System.out.println("After round 49");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            dVec = add(dVec, t1);
            hVec = add(t1, t2);

            t1 = add(gVec, Sigma1(dVec), ch(dVec, eVec, fVec), add(IntVector.broadcast(species, 0x1e376c08), w1 = inc(w1, sigma1(w15), w10, sigma0(w2))));
            t2 = add(Sigma0(hVec), maj(hVec, aVec, bVec));
            System.out.println("After round 50");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            cVec = add(cVec, t1);
            gVec = add(t1, t2);

            t1 = add(fVec, Sigma1(cVec), ch(cVec, dVec, eVec), add(IntVector.broadcast(species, 0x2748774c), w2 = inc(w2, sigma1(w0), w11, sigma0(w3))));
            t2  = add(Sigma0(gVec), maj(gVec, hVec, aVec));
            System.out.println("After round 51");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            bVec = add(bVec, t1);
            fVec = add(t1, t2);

            t1 = add(eVec, Sigma1(bVec), ch(bVec, cVec, dVec), add(IntVector.broadcast(species, 0x34b0bcb5), w3 = inc(w3, sigma1(w1), w12, sigma0(w4))));
            t2 = add(Sigma0(fVec), maj(fVec, gVec, hVec));
            System.out.println("After round 52");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            aVec = add(aVec, t1);
            eVec = add(t1, t2);

            t1 = add(dVec, Sigma1(aVec), ch(aVec, bVec, cVec), add(IntVector.broadcast(species, 0x391c0cb3), w4 = inc(w4, sigma1(w2), w13, sigma0(w5))));
            t2 = add(Sigma0(eVec), maj(eVec, fVec, gVec));
            System.out.println("After round 53");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            hVec = add(hVec, t1);
            dVec = add(t1, t2);

            t1 = add(cVec, Sigma1(hVec), ch(hVec, aVec, bVec), add(IntVector.broadcast(species, 0x4ed8aa4a), w5 = inc(w5, sigma1(w3), w14, sigma0(w6))));
            t2 = add(Sigma0(dVec), maj(dVec, eVec, fVec));
            System.out.println("After round 54");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            gVec = add(gVec, t1);
            cVec = add(t1, t2);

            t1 = add(bVec, Sigma1(gVec), ch(gVec, hVec, aVec), add(IntVector.broadcast(species, 0x5b9cca4f), w6 = inc(w6, sigma1(w4), w15, sigma0(w7))));
            t2 = add(Sigma0(cVec), maj(cVec, dVec, eVec));
            System.out.println("After round 55");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            fVec = add(fVec, t1);
            bVec = add(t1, t2);

            t1 = add(aVec, Sigma1(fVec), ch(fVec, gVec, hVec), add(IntVector.broadcast(species, 0x682e6ff3), w7 = inc(w7, sigma1(w5), w0, sigma0(w8))));
            t2 = add(Sigma0(bVec), maj(bVec, cVec, dVec));
            System.out.println("After round 56");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            eVec = add(eVec, t1);
            aVec = add(t1, t2);

            t1 = add(hVec, Sigma1(eVec), ch(eVec, fVec, gVec), add(IntVector.broadcast(species, 0x748f82ee), w8 = inc(w8, sigma1(w6), w1, sigma0(w9))));
            t2 = add(Sigma0(aVec), maj(aVec, bVec, cVec));
            System.out.println("After round 57");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            dVec = add(dVec, t1);
            hVec = add(t1, t2);

            t1 = add(gVec, Sigma1(dVec), ch(dVec, eVec, fVec), add(IntVector.broadcast(species, 0x78a5636f), w9 = inc(w9, sigma1(w7), w2, sigma0(w10))));
            t2 = add(Sigma0(hVec), maj(hVec, aVec, bVec));
            System.out.println("After round 58");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            cVec = add(cVec, t1);
            gVec = add(t1, t2);

            t1 = add(fVec, Sigma1(cVec), ch(cVec, dVec, eVec), add(IntVector.broadcast(species, 0x84c87814), w10 = inc(w10, sigma1(w8), w3, sigma0(w11))));
            t2 = add(Sigma0(gVec), maj(gVec, hVec, aVec));
            System.out.println("After round 59");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            bVec = add(bVec, t1);
            fVec = add(t1, t2);

            t1 = add(eVec, Sigma1(bVec), ch(bVec, cVec, dVec), add(IntVector.broadcast(species, 0x8cc70208), w11 = inc(w11, sigma1(w9), w4, sigma0(w12))));
            t2 = add(Sigma0(fVec), maj(fVec, gVec, hVec));
            System.out.println("After round 60");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            aVec = add(aVec, t1);
            eVec = add(t1, t2);

            t1 = add(dVec, Sigma1(aVec), ch(aVec, bVec, cVec), add(IntVector.broadcast(species, 0x90befffa), w12 = inc(w12, sigma1(w10), w5, sigma0(w13))));
            t2 = add(Sigma0(eVec), maj(eVec, fVec, gVec));
            System.out.println("After round 61");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            hVec = add(hVec, t1);
            dVec = add(t1, t2);

            t1 = add(cVec, Sigma1(hVec), ch(hVec, aVec, bVec), add(IntVector.broadcast(species, 0xa4506ceb), w13 = inc(w13, sigma1(w11), w6, sigma0(w14))));
            t2 = add(Sigma0(dVec), maj(dVec, eVec, fVec));
            System.out.println("After round 62");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            gVec = add(gVec, t1);
            cVec = add(t1, t2);

            t1 = add(bVec, Sigma1(gVec), ch(gVec, hVec, aVec), add(IntVector.broadcast(species, 0xbef9a3f7), w14 = inc(w14, sigma1(w12), w7, sigma0(w15))));
            t2 = add(Sigma0(cVec), maj(cVec, dVec, eVec));
            System.out.println("After round 63");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            fVec = add(fVec, t1);
            bVec = add(t1, t2);

            t1 = add(aVec, Sigma1(fVec), ch(fVec, gVec, hVec), add(IntVector.broadcast(species, 0xc67178f2), w15 = inc(w15, sigma1(w13), w8, sigma0(w0))));
            t2 = add(Sigma0(bVec), maj(bVec, cVec, dVec));
            System.out.println("After round 64");
            System.out.println("t1 = " + t1);
            System.out.println("t2 = " + t2);
            eVec = add(eVec, t1);
            aVec = add(t1, t2);

            aVec = add(aVec, IntVector.broadcast(species, H[0]));
            bVec = add(bVec, IntVector.broadcast(species, H[1]));
            cVec = add(cVec, IntVector.broadcast(species, H[2]));
            dVec = add(dVec, IntVector.broadcast(species, H[3]));
            eVec = add(eVec, IntVector.broadcast(species, H[4]));
            fVec = add(fVec, IntVector.broadcast(species, H[5]));
            gVec = add(gVec, IntVector.broadcast(species, H[6]));
            hVec = add(hVec, IntVector.broadcast(species, H[7]));

            // We are good to here, final a,b,c,d,e,f,g,h vectors match.
            System.out.println("a: " + Arrays.toString(aVec.toArray()));
            System.out.println("b: " + Arrays.toString(bVec.toArray()));
            System.out.println("c: " + Arrays.toString(cVec.toArray()));
            System.out.println("d: " + Arrays.toString(dVec.toArray()));
            System.out.println("e: " + Arrays.toString(eVec.toArray()));
            System.out.println("f: " + Arrays.toString(fVec.toArray()));
            System.out.println("g: " + Arrays.toString(gVec.toArray()));
            System.out.println("h: " + Arrays.toString(hVec.toArray()));

            byte[] hashes;
            if (species.vectorBitSize() == 256) {
                hashes = new byte[32 * 8];
                write8(hashes, 0, aVec);
                write8(hashes, 4, bVec);
                write8(hashes, 8, cVec);
                write8(hashes, 12, dVec);
                write8(hashes, 16, eVec);
                write8(hashes, 20, fVec);
                write8(hashes, 24, gVec);
                write8(hashes, 28, hVec);
            } else if (species.vectorBitSize() == 128) {
                hashes = new byte[32 * 4];
                write4(hashes, 0, aVec);
                write4(hashes, 4, bVec);
                write4(hashes, 8, cVec);
                write4(hashes, 12, dVec);
                write4(hashes, 16, eVec);
                write4(hashes, 20, fVec);
                write4(hashes, 24, gVec);
                write4(hashes, 28, hVec);
            } else {
                throw new RuntimeException("not implemented");
            }
            /*
            <MacGyver> That does look rather odd, yes, but it looks like it's computing 8 hashes vectorized.
            <MacGyver> The result after those 8 calls to Write8 is 8 hashes back-to-back in out.
             */
            // FIXME: Instead of writing to hashes we can just set H from the bytes the last hash (H[7])
            H[0] = bytesToIntLE(hashes, 224);
            H[1] = bytesToIntLE(hashes, 228);
            H[2] = bytesToIntLE(hashes, 232);
            H[3] = bytesToIntLE(hashes, 236);
            H[4] = bytesToIntLE(hashes, 240);
            H[5] = bytesToIntLE(hashes, 244);
            H[6] = bytesToIntLE(hashes, 248);
            H[7] = bytesToIntLE(hashes, 252);
        }
    }

}