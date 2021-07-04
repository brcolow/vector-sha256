package com.brcolow.vectorsha256;

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
        byte[] jdkHash = digest.digest(toHash);
        System.out.println("JDK hash: " + bytesToHex(jdkHash));
        //System.out.println("data.length: " + data.length);
        byte[] out = new byte[32];
        Sha256Digest sha256Digest = new Sha256Digest();
        // sha256Digest.transform_8way("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxy".getBytes(StandardCharsets.UTF_8), out);

        sha256Digest.update(toHash, 0, toHash.length);
        sha256Digest.digest(out, 0, 32);
        System.out.println("hash out: " + bytesToHex(out));
        //sha256Digest.transform_8way(data, out);
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
        private IntVector dVec;
        private IntVector hVec;
        private int d;
        private int h;
        private int[] H;
        // buffer to store partial blocks, 64 bytes large
        byte[] buffer;
        // offset into buffer
        private int bufOfs;
        // size of the input to the compression function (transform) in bytes
        private final int blockSize8x = 64 * 8;
        private final int blockSize4x = 64 * 4;
        private final int blockSize2x = 64 * 2;
        private final int blockSize =   64;
        // length of the message digest in bytes
        private final int digestLength = 32;
        long bytesProcessed;
        static final byte[] padding;

        static {
            // we need 128 byte padding for SHA-384/512
            padding = new byte[128];
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

        /**
         * byte[] to int[] conversion, little endian byte order.
         */
        static void b2iLittle(byte[] in, int inOfs, int[] out, int outOfs, int len) {
            len += inOfs;
            while (inOfs < len) {
                out[outOfs++] = (int) LE.INT_ARRAY.get(in, inOfs);
                inOfs += 4;
            }
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
            System.out.println("bytesProcessed: " + bytesProcessed);
            System.out.println("bitsProcessed: " + bitsProcessed);
            System.out.println("index: " + index);
            int padLen = (index < 56) ? (56 - index) : (120 - index);
            System.out.println("padding length: " + padLen);
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
            System.out.println("update\n");
            System.out.println("in: " + bytesToHex(in));
            System.out.println("inOff: " + inOff);
            System.out.println("len: " + len);
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
                for (; inOff <= limit; inOff += blockSize8x) {
                    transform_multi_way(in, SPECIES_256, this::read8);
                    byte[] hash = new byte[digestLength];
                    intArrToBytesBE(H, hash, digestLength);
                    System.out.println("H[] after 8way transform: " + bytesToHex(hash));
                }
                len = limit - inOff;
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
            System.out.println("buffer: " + bytesToHex(buffer));
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

        byte[] intToBytesBE(int value) {
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
                    bytesToIntLE(chunk, 32 + offset),
                    bytesToIntLE(chunk, 64 + offset),
                    bytesToIntLE(chunk, 96 + offset)
            }, 0);
            // VectorShuffle<Byte> HIGHTOLOW =  VectorShuffle.fromOp(SPECIES, (i -> ((8+i)%16)));
            var shuffle = VectorShuffle.fromArray(SPECIES_128, new int[]{
                    12,13,14,15,   8, 9,10,11,
                    4, 5, 6, 7,    0, 1, 2, 3
            }, 0);
            ret.rearrange(shuffle, shuffle.laneIsValid());
            return ret;
        }

        IntVector read8(byte[] chunk, int offset) {
            System.out.println("read8, offset = " + offset);
            System.out.println("chunk: " + Arrays.toString(chunk));
            IntVector ret = IntVector.fromArray(SPECIES_256, new int[] {
                    bytesToIntLE(chunk, 0 + offset),
                    bytesToIntLE(chunk, 16 + offset),
                    bytesToIntLE(chunk, 32 + offset),
                    bytesToIntLE(chunk, 48 + offset),
                    bytesToIntLE(chunk, 64 + offset),
                    bytesToIntLE(chunk, 80 + offset),
                    bytesToIntLE(chunk, 96 + offset),
                    bytesToIntLE(chunk, 112 + offset)}, 0);
            // var shuffle = VectorShuffle.fromArray(SPECIES_256, new int[]{0x0C0D0E0F, 0x08090A0B, 0x04050607, 0x00010203, 0x0C0D0E0F, 0x08090A0B, 0x04050607, 0x00010203 }, 0);
            var shuffle = VectorShuffle.fromArray(SPECIES_256, new int[]{
                    12,13,14,15,   8, 9,10,11,
                    4, 5, 6, 7,    0, 1, 2, 3,
                    12,13,14,15,   8, 9,10,11,
                    4, 5, 6, 7,    0, 1, 2, 3 }, 0);
            ret.rearrange(shuffle, shuffle.laneIsValid());
            return ret;
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
            // var shuffle = VectorShuffle.fromArray(SPECIES_256, new int[]{0x0C0D0E0F, 0x08090A0B, 0x04050607, 0x00010203, 0x0C0D0E0F, 0x08090A0B, 0x04050607, 0x00010203 }, 0);
            var shuffle = VectorShuffle.fromArray(SPECIES_256, new int[]{
                    12,13,14,15,   8, 9,10,11,
                    4, 5, 6, 7,    0, 1, 2, 3,
                    12,13,14,15,   8, 9,10,11,
                    4, 5, 6, 7,    0, 1, 2, 3 }, 0);
            v.rearrange(shuffle, shuffle.laneIsValid());
            System.arraycopy(intToBytesLE(v.lane(7)), 0, out, 0 + offset, 4);
            System.arraycopy(intToBytesLE(v.lane(6)), 0, out, 32 + offset, 4);
            System.arraycopy(intToBytesLE(v.lane(5)), 0, out, 64 + offset, 4);
            System.arraycopy(intToBytesLE(v.lane(4)), 0, out, 96 + offset, 4);
            System.arraycopy(intToBytesLE(v.lane(3)), 0, out, 128 + offset, 4);
            System.arraycopy(intToBytesLE(v.lane(2)), 0, out, 160 + offset, 4);
            System.arraycopy(intToBytesLE(v.lane(1)), 0, out, 192 + offset, 4);
            System.arraycopy(intToBytesLE(v.lane(0)), 0, out, 224 + offset, 4);
            System.out.println("out: " + Arrays.toString(out));
        }

        private void round(IntVector a, IntVector b, IntVector c, IntVector d, IntVector e, IntVector f, IntVector g, IntVector h, IntVector k) {
            IntVector t1 = add(h, Sigma1(e), ch(e, f, g), k);
            IntVector t2 = add(Sigma0(a), maj(a, b, c));
            this.dVec = add(d, t1);
            this.hVec = add(t1, t2);
        }

        private void round(int a, int b, int c, int d, int e, int f, int g, int h, int k) {
            int t1 = h + Sigma1(e) + ch(e, f, g) + k;
            int t2 = Sigma0(a) + maj(a, b, c);
            this.d = d + t1;
            this.h = t1 + t2;
        }

        /**
         * Takes a 64-byte chunk.
         * @param in
         */
        private void transform(byte[] in) {
            int a = H[0];
            int b = H[1];
            int c = H[2];
            int d = H[3];
            int e = H[4];
            int f = H[5];
            int g = H[6];
            int h = H[7];

            int w0 = bytesToIntBE(in, 0);
            round(a, b, c, d, e, f, g, h, 0x428a2f98 + w0);

            int w1 = bytesToIntBE(in, 4);
            round(h, a, b, c, d, e, f, g, 0x71374491 + w1);

            int w2 = bytesToIntBE(in, 8);
            round(g, h, a, b, c, d, e, f, 0xb5c0fbcf + w2);

            int w3 = bytesToIntBE(in, 12);
            round(f, g, h, a, b, c, d, e, 0xe9b5dba5 + w3);

            int w4 = bytesToIntBE(in, 16);
            round(e, f, g, h, a, b, c, d, 0x3956c25b + w4);

            int w5 = bytesToIntBE(in, 20);
            round(d, e, f, g, h, a, b, c, 0x59f111f1 + w5);

            int w6 = bytesToIntBE(in, 24);
            round(c, d, e, f, g, h, a, b, 0x923f82a4 + w6);

            int w7 = bytesToIntBE(in, 28);
            round(b, c, d, e, f, g, h, a, 0xab1c5ed5 + w7);

            int w8 = bytesToIntBE(in, 32);
            round(a, b, c, d, e, f, g, h, 0xd807aa98 + w8);

            int w9 = bytesToIntBE(in, 36);
            round(h, a, b, c, d, e, f, g, 0x12835b01 + w9);

            int w10 = bytesToIntBE(in, 40);
            round(g, h, a, b, c, d, e, f, 0x243185be + w10);

            int w11 = bytesToIntBE(in, 44);
            round(f, g, h, a, b, c, d, e, 0x550c7dc3 + w11);

            int w12 = bytesToIntBE(in, 48);
            round(e, f, g, h, a, b, c, d, 0x72be5d74 + w12);

            int w13 = bytesToIntBE(in, 52);
            round(d, e, f, g, h, a, b, c, 0x80deb1fe + w13);

            int w14 = bytesToIntBE(in, 56);
            round(c, d, e, f, g, h, a, b, 0x9bdc06a7 + w14);

            int w15 = bytesToIntBE(in, 60);
            round(b, c, d, e, f, g, h, a, 0xc19bf174 + w15);

            round(a, b, c, d, e, f, g, h, 0xe49b69c1 + (w0 += sigma1(w14) + w9 + sigma0(w1)));
            round(h, a, b, c, d, e, f, g, 0xefbe4786 + (w1 += sigma1(w15) + w10 + sigma0(w2)));
            round(g, h, a, b, c, d, e, f, 0x0fc19dc6 + (w2 += sigma1(w0) + w11 + sigma0(w3)));
            round(f, g, h, a, b, c, d, e, 0x240ca1cc + (w3 += sigma1(w1) + w12 + sigma0(w4)));
            round(e, f, g, h, a, b, c, d, 0x2de92c6f + (w4 += sigma1(w2) + w13 + sigma0(w5)));
            round(d, e, f, g, h, a, b, c, 0x4a7484aa + (w5 += sigma1(w3) + w14 + sigma0(w6)));
            round(c, d, e, f, g, h, a, b, 0x5cb0a9dc + (w6 += sigma1(w4) + w15 + sigma0(w7)));
            round(b, c, d, e, f, g, h, a, 0x76f988da + (w7 += sigma1(w5) + w0 + sigma0(w8)));
            round(a, b, c, d, e, f, g, h, 0x983e5152 + (w8 += sigma1(w6) + w1 + sigma0(w9)));
            round(h, a, b, c, d, e, f, g, 0xa831c66d + (w9 += sigma1(w7) + w2 + sigma0(w10)));
            round(g, h, a, b, c, d, e, f, 0xb00327c8 + (w10 += sigma1(w8) + w3 + sigma0(w11)));
            round(f, g, h, a, b, c, d, e, 0xbf597fc7 + (w11 += sigma1(w9) + w4 + sigma0(w12)));
            round(e, f, g, h, a, b, c, d, 0xc6e00bf3 + (w12 += sigma1(w10) + w5 + sigma0(w13)));
            round(d, e, f, g, h, a, b, c, 0xd5a79147 + (w13 += sigma1(w11) + w6 + sigma0(w14)));
            round(c, d, e, f, g, h, a, b, 0x06ca6351 + (w14 += sigma1(w12) + w7 + sigma0(w15)));
            round(b, c, d, e, f, g, h, a, 0x14292967 + (w15 += sigma1(w13) + w8 + sigma0(w0)));

            round(a, b, c, d, e, f, g, h, 0x27b70a85 + (w0 += sigma1(w14) + w9 + sigma0(w1)));
            round(h, a, b, c, d, e, f, g, 0x2e1b2138 + (w1 += sigma1(w15) + w10 + sigma0(w2)));
            round(g, h, a, b, c, d, e, f, 0x4d2c6dfc + (w2 += sigma1(w0) + w11 + sigma0(w3)));
            round(f, g, h, a, b, c, d, e, 0x53380d13 + (w3 += sigma1(w1) + w12 + sigma0(w4)));
            round(e, f, g, h, a, b, c, d, 0x650a7354 + (w4 += sigma1(w2) + w13 + sigma0(w5)));
            round(d, e, f, g, h, a, b, c, 0x766a0abb + (w5 += sigma1(w3) + w14 + sigma0(w6)));
            round(c, d, e, f, g, h, a, b, 0x81c2c92e + (w6 += sigma1(w4) + w15 + sigma0(w7)));
            round(b, c, d, e, f, g, h, a, 0x92722c85 + (w7 += sigma1(w5) + w0 + sigma0(w8)));
            round(a, b, c, d, e, f, g, h, 0xa2bfe8a1 + (w8 += sigma1(w6) + w1 + sigma0(w9)));
            round(h, a, b, c, d, e, f, g, 0xa81a664b + (w9 += sigma1(w7) + w2 + sigma0(w10)));
            round(g, h, a, b, c, d, e, f, 0xc24b8b70 + (w10 += sigma1(w8) + w3 + sigma0(w11)));
            round(f, g, h, a, b, c, d, e, 0xc76c51a3 + (w11 += sigma1(w9) + w4 + sigma0(w12)));
            round(e, f, g, h, a, b, c, d, 0xd192e819 + (w12 += sigma1(w10) + w5 + sigma0(w13)));
            round(d, e, f, g, h, a, b, c, 0xd6990624 + (w13 += sigma1(w11) + w6 + sigma0(w14)));
            round(c, d, e, f, g, h, a, b, 0xf40e3585 + (w14 += sigma1(w12) + w7 + sigma0(w15)));
            round(b, c, d, e, f, g, h, a, 0x106aa070 + (w15 += sigma1(w13) + w8 + sigma0(w0)));

            round(a, b, c, d, e, f, g, h, 0x19a4c116 + (w0 += sigma1(w14) + w9 + sigma0(w1)));
            round(h, a, b, c, d, e, f, g, 0x1e376c08 + (w1 += sigma1(w15) + w10 + sigma0(w2)));
            round(g, h, a, b, c, d, e, f, 0x2748774c + (w2 += sigma1(w0) + w11 + sigma0(w3)));
            round(f, g, h, a, b, c, d, e, 0x34b0bcb5 + (w3 += sigma1(w1) + w12 + sigma0(w4)));
            round(e, f, g, h, a, b, c, d, 0x391c0cb3 + (w4 += sigma1(w2) + w13 + sigma0(w5)));
            round(d, e, f, g, h, a, b, c, 0x4ed8aa4a + (w5 += sigma1(w3) + w14 + sigma0(w6)));
            round(c, d, e, f, g, h, a, b, 0x5b9cca4f + (w6 += sigma1(w4) + w15 + sigma0(w7)));
            round(b, c, d, e, f, g, h, a, 0x682e6ff3 + (w7 += sigma1(w5) + w0 + sigma0(w8)));
            round(a, b, c, d, e, f, g, h, 0x748f82ee + (w8 += sigma1(w6) + w1 + sigma0(w9)));
            round(h, a, b, c, d, e, f, g, 0x78a5636f + (w9 += sigma1(w7) + w2 + sigma0(w10)));
            round(g, h, a, b, c, d, e, f, 0x84c87814 + (w10 += sigma1(w8) + w3 + sigma0(w11)));
            round(f, g, h, a, b, c, d, e, 0x8cc70208 + (w11 += sigma1(w9) + w4 + sigma0(w12)));
            round(e, f, g, h, a, b, c, d, 0x90befffa + (w12 += sigma1(w10) + w5 + sigma0(w13)));
            round(d, e, f, g, h, a, b, c, 0xa4506ceb + (w13 += sigma1(w11) + w6 + sigma0(w14)));
            round(c, d, e, f, g, h, a, b, 0xbef9a3f7 + (w14 + sigma1(w12) + w7 + sigma0(w15)));
            round(b, c, d, e, f, g, h, a, 0xc67178f2 + (w15 + sigma1(w13) + w8 + sigma0(w0)));

            H[0] += a;
            H[1] += b;
            H[2] += c;
            H[3] += d;
            H[4] += e;
            H[5] += f;
            H[6] += g;
            H[7] += h;
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
            round(aVec, bVec, cVec, dVec, eVec, fVec, gVec, hVec, add(IntVector.broadcast(species, 0x428a2f98), w0));

            IntVector w1 = readFunc.apply(in, 4);
            round(hVec, aVec, bVec, cVec, dVec, eVec, fVec, gVec, add(IntVector.broadcast(species, 0x71374491), w1));

            IntVector w2 = readFunc.apply(in, 8);
            round(gVec, hVec, aVec, bVec, cVec, dVec, eVec, fVec, add(IntVector.broadcast(species, 0xb5c0fbcf), w2));

            IntVector w3 = readFunc.apply(in, 12);
            round(fVec, gVec, hVec, aVec, bVec, cVec, dVec, eVec, add(IntVector.broadcast(species, 0xe9b5dba5), w3));

            IntVector w4 = readFunc.apply(in, 16);
            round(eVec, fVec, gVec, hVec, aVec, bVec, cVec, dVec, add(IntVector.broadcast(species, 0x3956c25b), w4));

            IntVector w5 = readFunc.apply(in, 20);
            round(dVec, eVec, fVec, gVec, hVec, aVec, bVec, cVec, add(IntVector.broadcast(species, 0x59f111f1), w5));

            IntVector w6 = readFunc.apply(in, 24);
            round(cVec, dVec, eVec, fVec, gVec, hVec, aVec, bVec, add(IntVector.broadcast(species, 0x923f82a4), w6));

            IntVector w7 = readFunc.apply(in, 28);
            round(bVec, cVec, dVec, eVec, fVec, gVec, hVec, aVec, add(IntVector.broadcast(species, 0xab1c5ed5), w7));

            IntVector w8 = readFunc.apply(in, 32);
            round(aVec, bVec, cVec, dVec, eVec, fVec, gVec, hVec, add(IntVector.broadcast(species, 0xd807aa98), w8));

            IntVector w9 = readFunc.apply(in, 36);
            round(hVec, aVec, bVec, cVec, dVec, eVec, fVec, gVec, add(IntVector.broadcast(species, 0x12835b01), w9));

            IntVector w10 = readFunc.apply(in, 40);
            round(gVec, hVec, aVec, bVec, cVec, dVec, eVec, fVec, add(IntVector.broadcast(species, 0x243185be), w10));

            IntVector w11 = readFunc.apply(in, 44);
            round(fVec, gVec, hVec, aVec, bVec, cVec, dVec, eVec, add(IntVector.broadcast(species, 0x550c7dc3), w11));

            IntVector w12 = readFunc.apply(in, 48);
            round(eVec, fVec, gVec, hVec, aVec, bVec, cVec, dVec, add(IntVector.broadcast(species, 0x72be5d74), w12));

            IntVector w13 = readFunc.apply(in, 52);
            round(dVec, eVec, fVec, gVec, hVec, aVec, bVec, cVec, add(IntVector.broadcast(species, 0x80deb1fe), w13));

            IntVector w14 = readFunc.apply(in, 56);
            round(cVec, dVec, eVec, fVec, gVec, hVec, aVec, bVec, add(IntVector.broadcast(species, 0x9bdc06a7), w14));

            IntVector w15 = readFunc.apply(in, 60);
            round(bVec, cVec, dVec, eVec, fVec, gVec, hVec, aVec, add(IntVector.broadcast(species, 0xc19bf174), w15));

            round(aVec, bVec, cVec, dVec, eVec, fVec, gVec, hVec, add(IntVector.broadcast(species, 0xe49b69c1), inc(w0, sigma1(w14), w9, sigma0(w1))));
            round(hVec, aVec, bVec, cVec, dVec, eVec, fVec, gVec, add(IntVector.broadcast(species, 0xefbe4786), inc(w1, sigma1(w15), w10, sigma0(w2))));
            round(gVec, hVec, aVec, bVec, cVec, dVec, eVec, fVec, add(IntVector.broadcast(species, 0x0fc19dc6), inc(w2, sigma1(w0), w11, sigma0(w3))));
            round(fVec, gVec, hVec, aVec, bVec, cVec, dVec, eVec, add(IntVector.broadcast(species, 0x240ca1cc), inc(w3, sigma1(w1), w12, sigma0(w4))));
            round(eVec, fVec, gVec, hVec, aVec, bVec, cVec, dVec, add(IntVector.broadcast(species, 0x2de92c6f), inc(w4, sigma1(w2), w13, sigma0(w5))));
            round(dVec, eVec, fVec, gVec, hVec, aVec, bVec, cVec, add(IntVector.broadcast(species, 0x4a7484aa), inc(w5, sigma1(w3), w14, sigma0(w6))));
            round(cVec, dVec, eVec, fVec, gVec, hVec, aVec, bVec, add(IntVector.broadcast(species, 0x5cb0a9dc), inc(w6, sigma1(w4), w15, sigma0(w7))));
            round(bVec, cVec, dVec, eVec, fVec, gVec, hVec, aVec, add(IntVector.broadcast(species, 0x76f988da), inc(w7, sigma1(w5), w0, sigma0(w8))));
            round(aVec, bVec, cVec, dVec, eVec, fVec, gVec, hVec, add(IntVector.broadcast(species, 0x983e5152), inc(w8, sigma1(w6), w1, sigma0(w9))));
            round(hVec, aVec, bVec, cVec, dVec, eVec, fVec, gVec, add(IntVector.broadcast(species, 0xa831c66d), inc(w9, sigma1(w7), w2, sigma0(w10))));
            round(gVec, hVec, aVec, bVec, cVec, dVec, eVec, fVec, add(IntVector.broadcast(species, 0xb00327c8), inc(w10, sigma1(w8), w3, sigma0(w11))));
            round(fVec, gVec, hVec, aVec, bVec, cVec, dVec, eVec, add(IntVector.broadcast(species, 0xbf597fc7), inc(w11, sigma1(w9), w4, sigma0(w12))));
            round(eVec, fVec, gVec, hVec, aVec, bVec, cVec, dVec, add(IntVector.broadcast(species, 0xc6e00bf3), inc(w12, sigma1(w10), w5, sigma0(w13))));
            round(dVec, eVec, fVec, gVec, hVec, aVec, bVec, cVec, add(IntVector.broadcast(species, 0xd5a79147), inc(w13, sigma1(w11), w6, sigma0(w14))));
            round(cVec, dVec, eVec, fVec, gVec, hVec, aVec, bVec, add(IntVector.broadcast(species, 0x06ca6351), inc(w14, sigma1(w12), w7, sigma0(w15))));
            round(bVec, cVec, dVec, eVec, fVec, gVec, hVec, aVec, add(IntVector.broadcast(species, 0x14292967), inc(w15, sigma1(w13), w8, sigma0(w0))));
            round(aVec, bVec, cVec, dVec, eVec, fVec, gVec, hVec, add(IntVector.broadcast(species, 0x27b70a85), inc(w0, sigma1(w14), w9, sigma0(w1))));
            round(hVec, aVec, bVec, cVec, dVec, eVec, fVec, gVec, add(IntVector.broadcast(species, 0x2e1b2138), inc(w1, sigma1(w15), w10, sigma0(w2))));
            round(gVec, hVec, aVec, bVec, cVec, dVec, eVec, fVec, add(IntVector.broadcast(species, 0x4d2c6dfc), inc(w2, sigma1(w0), w11, sigma0(w3))));
            round(fVec, gVec, hVec, aVec, bVec, cVec, dVec, eVec, add(IntVector.broadcast(species, 0x53380d13), inc(w3, sigma1(w1), w12, sigma0(w4))));
            round(eVec, fVec, gVec, hVec, aVec, bVec, cVec, dVec, add(IntVector.broadcast(species, 0x650a7354), inc(w4, sigma1(w2), w13, sigma0(w5))));
            round(dVec, eVec, fVec, gVec, hVec, aVec, bVec, cVec, add(IntVector.broadcast(species, 0x766a0abb), inc(w5, sigma1(w3), w14, sigma0(w6))));
            round(cVec, dVec, eVec, fVec, gVec, hVec, aVec, bVec, add(IntVector.broadcast(species, 0x81c2c92e), inc(w6, sigma1(w4), w15, sigma0(w7))));
            round(bVec, cVec, dVec, eVec, fVec, gVec, hVec, aVec, add(IntVector.broadcast(species, 0x92722c85), inc(w7, sigma1(w5), w0, sigma0(w8))));
            round(aVec, bVec, cVec, dVec, eVec, fVec, gVec, hVec, add(IntVector.broadcast(species, 0xa2bfe8a1), inc(w8, sigma1(w6), w1, sigma0(w9))));
            round(hVec, aVec, bVec, cVec, dVec, eVec, fVec, gVec, add(IntVector.broadcast(species, 0xa81a664b), inc(w9, sigma1(w7), w2, sigma0(w10))));
            round(gVec, hVec, aVec, bVec, cVec, dVec, eVec, fVec, add(IntVector.broadcast(species, 0xc24b8b70), inc(w10, sigma1(w8), w3, sigma0(w11))));
            round(fVec, gVec, hVec, aVec, bVec, cVec, dVec, eVec, add(IntVector.broadcast(species, 0xc76c51a3), inc(w11, sigma1(w9), w4, sigma0(w12))));
            round(eVec, fVec, gVec, hVec, aVec, bVec, cVec, dVec, add(IntVector.broadcast(species, 0xd192e819), inc(w12, sigma1(w10), w5, sigma0(w13))));
            round(dVec, eVec, fVec, gVec, hVec, aVec, bVec, cVec, add(IntVector.broadcast(species, 0xd6990624), inc(w13, sigma1(w11), w6, sigma0(w14))));
            round(cVec, dVec, eVec, fVec, gVec, hVec, aVec, bVec, add(IntVector.broadcast(species, 0xf40e3585), inc(w14, sigma1(w12), w7, sigma0(w15))));
            round(bVec, cVec, dVec, eVec, fVec, gVec, hVec, aVec, add(IntVector.broadcast(species, 0x106aa070), inc(w15, sigma1(w13), w8, sigma0(w0))));
            round(aVec, bVec, cVec, dVec, eVec, fVec, gVec, hVec, add(IntVector.broadcast(species, 0x19a4c116), inc(w0, sigma1(w14), w9, sigma0(w1))));
            round(hVec, aVec, bVec, cVec, dVec, eVec, fVec, gVec, add(IntVector.broadcast(species, 0x1e376c08), inc(w1, sigma1(w15), w10, sigma0(w2))));
            round(gVec, hVec, aVec, bVec, cVec, dVec, eVec, fVec, add(IntVector.broadcast(species, 0x2748774c), inc(w2, sigma1(w0), w11, sigma0(w3))));
            round(fVec, gVec, hVec, aVec, bVec, cVec, dVec, eVec, add(IntVector.broadcast(species, 0x34b0bcb5), inc(w3, sigma1(w1), w12, sigma0(w4))));
            round(eVec, fVec, gVec, hVec, aVec, bVec, cVec, dVec, add(IntVector.broadcast(species, 0x391c0cb3), inc(w4, sigma1(w2), w13, sigma0(w5))));
            round(dVec, eVec, fVec, gVec, hVec, aVec, bVec, cVec, add(IntVector.broadcast(species, 0x4ed8aa4a), inc(w5, sigma1(w3), w14, sigma0(w6))));
            round(cVec, dVec, eVec, fVec, gVec, hVec, aVec, bVec, add(IntVector.broadcast(species, 0x5b9cca4f), inc(w6, sigma1(w4), w15, sigma0(w7))));
            round(bVec, cVec, dVec, eVec, fVec, gVec, hVec, aVec, add(IntVector.broadcast(species, 0x682e6ff3), inc(w7, sigma1(w5), w0, sigma0(w8))));
            round(aVec, bVec, cVec, dVec, eVec, fVec, gVec, hVec, add(IntVector.broadcast(species, 0x748f82ee), inc(w8, sigma1(w6), w1, sigma0(w9))));
            round(hVec, aVec, bVec, cVec, dVec, eVec, fVec, gVec, add(IntVector.broadcast(species, 0x78a5636f), inc(w9, sigma1(w7), w2, sigma0(w10))));
            round(gVec, hVec, aVec, bVec, cVec, dVec, eVec, fVec, add(IntVector.broadcast(species, 0x84c87814), inc(w10, sigma1(w8), w3, sigma0(w11))));
            round(fVec, gVec, hVec, aVec, bVec, cVec, dVec, eVec, add(IntVector.broadcast(species, 0x8cc70208), inc(w11, sigma1(w9), w4, sigma0(w12))));
            round(eVec, fVec, gVec, hVec, aVec, bVec, cVec, dVec, add(IntVector.broadcast(species, 0x90befffa), inc(w12, sigma1(w10), w5, sigma0(w13))));
            round(dVec, eVec, fVec, gVec, hVec, aVec, bVec, cVec, add(IntVector.broadcast(species, 0xa4506ceb), inc(w13, sigma1(w11), w6, sigma0(w14))));
            round(cVec, dVec, eVec, fVec, gVec, hVec, aVec, bVec, add(IntVector.broadcast(species, 0xbef9a3f7), inc(w14, sigma1(w12), w7, sigma0(w15))));
            round(bVec, cVec, dVec, eVec, fVec, gVec, hVec, aVec, add(IntVector.broadcast(species, 0xc67178f2), inc(w15, sigma1(w13), w8, sigma0(w0))));

            aVec = add(aVec, IntVector.broadcast(species, H[0]));
            bVec = add(bVec, IntVector.broadcast(species, H[1]));
            cVec = add(cVec, IntVector.broadcast(species, H[2]));
            dVec = add(dVec, IntVector.broadcast(species, H[3]));
            eVec = add(eVec, IntVector.broadcast(species, H[4]));
            fVec = add(fVec, IntVector.broadcast(species, H[5]));
            gVec = add(gVec, IntVector.broadcast(species, H[6]));
            hVec = add(hVec, IntVector.broadcast(species, H[7]));

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
                write8(hashes, 0, add(aVec, IntVector.broadcast(species, H[0])));
                write8(hashes, 4, add(bVec, IntVector.broadcast(species, H[1])));
                write8(hashes, 8, add(cVec, IntVector.broadcast(species, H[2])));
                write8(hashes, 12, add(dVec, IntVector.broadcast(species, H[3])));
                write8(hashes, 16, add(eVec, IntVector.broadcast(species, H[4])));
                write8(hashes, 20, add(fVec, IntVector.broadcast(species, H[5])));
                write8(hashes, 24, add(gVec, IntVector.broadcast(species, H[6])));
                write8(hashes, 28, add(hVec, IntVector.broadcast(species, H[7])));
            } else if (species.vectorBitSize() == 128) {
                hashes = new byte[32 * 4];
                write4(hashes, 0, add(aVec, IntVector.broadcast(species, H[0])));
                write4(hashes, 4, add(bVec, IntVector.broadcast(species, H[1])));
                write4(hashes, 8, add(cVec, IntVector.broadcast(species, H[2])));
                write4(hashes, 12, add(dVec, IntVector.broadcast(species, H[3])));
                write4(hashes, 16, add(eVec, IntVector.broadcast(species, H[4])));
                write4(hashes, 20, add(fVec, IntVector.broadcast(species, H[5])));
                write4(hashes, 24, add(gVec, IntVector.broadcast(species, H[6])));
                write4(hashes, 28, add(hVec, IntVector.broadcast(species, H[7])));
            } else {
                throw new RuntimeException("not implemented");
            }
            /*
            <MacGyver> That does look rather odd, yes, but it looks like it's computing 8 hashes vectorized.
            <MacGyver> The result after those 8 calls to Write8 is 8 hashes back-to-back in out.
             */
            // FIXME: Instead of writing to hashes we can just set H from the bytes the last hash (h?)
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