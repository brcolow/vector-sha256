package com.brcolow.vectorsha256;

import jdk.incubator.vector.IntVector;
import jdk.incubator.vector.VectorOperators;
import jdk.incubator.vector.VectorShuffle;
import jdk.incubator.vector.VectorSpecies;

import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

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
 */
public class VectorSHA256 {
    static final VectorSpecies<Integer> SPECIES_256 = IntVector.SPECIES_256;
    static byte[] data = ("-" +
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do " +
            "eiusmod tempor incididunt ut labore et dolore magna aliqua. Et m" +
            "olestie ac feugiat sed lectus vestibulum mattis ullamcorper. Mor" +
            "bi blandit cursus risus at ultrices mi tempus imperdiet nulla. N" +
            "unc congue nisi vita suscipit tellus mauris. Imperdiet proin fer" +
            "mentum leo vel orci. Massa tempor nec feugiat nisl pretium fusce" +
            " id velit. Telus in metus vulputate eu scelerisque felis. Mi tem" +
            "pus imperdiet nulla malesuada pellentesque. Tristique magna sit.").getBytes(StandardCharsets.US_ASCII);
    public static void main(String[] args) {
        //System.out.println("data.length: " + data.length);
        byte[] out = new byte[32];
        Sha256Digest sha256Digest = new Sha256Digest();
        // sha256Digest.transform_8way("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxy".getBytes(StandardCharsets.UTF_8), out);
        byte[] toHash = ("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxy" +
                "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxy").getBytes(StandardCharsets.US_ASCII);
        sha256Digest.update(toHash, 0, toHash.length);
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
        private IntVector d;
        private IntVector h;
        private int[] state;
        // buffer to store partial blocks, blockSize bytes large
        byte[] buffer;
        // offset into buffer
        private int bufOfs;
        // size of the input to the compression function (transform) in bytes
        private final int blockSize = 256;
        // length of the message digest in bytes
        private final int digestLength = 32;
        long bytesProcessed;

        private static final int[] INITIAL_HASHES = {
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        };

        public Sha256Digest() {
            buffer = new byte[blockSize];
            state = new int[8];
            resetHashes();
        }

        private void resetHashes() {
            System.arraycopy(INITIAL_HASHES, 0, state, 0, state.length);
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
                System.out.println("bufOfs != 0");
                int n = Math.min(len, blockSize - bufOfs);
                System.arraycopy(in, inOff, buffer, bufOfs, n);
                bufOfs += n;
                inOff += n;
                len -= n;
                if (bufOfs >= blockSize) {
                    // compress completed block now
                    byte[] out = new byte[256];
                    transform_8way(buffer, out);
                    System.arraycopy(out, 0, buffer, 0, 256);
                    bufOfs = 0;
                }
            }

            if (len >= blockSize) {
                System.out.println("len >= blockSize");
                int limit = inOff + len;
                for (; inOff <= limit; inOff += blockSize) {
                    byte[] out = new byte[256];
                    transform_8way(in, out);
                    System.arraycopy(out, 0, buffer, 0, 256);
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

        public void finish() {
            // TODO
        }

        IntVector add(IntVector x, IntVector y) {
            return x.add(y);
        }

        IntVector add(IntVector x, IntVector y, IntVector z) {
            return add(add(x, y), z);
        }

        IntVector add(IntVector x, IntVector y, IntVector z, IntVector w) {
            return add(add(x, y), add(z, w));
        }

        IntVector add(IntVector x, IntVector y, IntVector z, IntVector w, IntVector v) {
            return add(add(x, y, z), add(w, v));
        }

        IntVector inc(IntVector x, IntVector y) {
            return add(x, y);
        }

        IntVector inc(IntVector x, IntVector y, IntVector z) {
            return add(x, y, z);
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

        IntVector maj(IntVector x, IntVector y, IntVector z) {
            return or(and(x, y), and(z, or(x, y)));
        }

        IntVector Sigma0(IntVector x) {
            return xor(or(shR(x, 2), shL(x, 30)), or(shR(x, 13), shL(x, 19)), or(shR(x, 22), shL(x, 10)));
        }

        IntVector Sigma1(IntVector x) {
            return xor(or(shR(x, 6), shL(x, 26)), or(shR(x, 11), shL(x, 21)), or(shR(x, 25), shL(x, 7)));
        }

        IntVector sigma0(IntVector x) {
            return xor(or(shR(x, 7), shL(x, 25)), or(shR(x, 18), shL(x, 14)), shR(x, 3));
        }

        IntVector sigma1(IntVector x) {
            return xor(or(shR(x, 17), shL(x, 15)), or(shR(x, 19), shL(x, 13)), shR(x, 10));
        }

        IntVector read8(byte[] chunk) {
            // This may be messing up endianess.
            System.out.println("chunk: " + Arrays.toString(chunk));
            //IntVector ret = IntVector.fromArray(SPECIES_256, chunk, offset);
            IntVector ret = IntVector.fromArray(SPECIES_256, new int[] {chunk[7], chunk[6], chunk[5], chunk[4], chunk[3], chunk[2], chunk[1], chunk[0]}, 0);
            // var shuffle = VectorShuffle.fromArray(SPECIES_256, new int[]{0x0C0D0E0F, 0x08090A0B, 0x04050607, 0x00010203, 0x0C0D0E0F, 0x08090A0B, 0x04050607, 0x00010203 }, 0);
            var shuffle = VectorShuffle.fromArray(SPECIES_256, new int[]{
                    12,13,14,15,   8, 9,10,11,
                    4, 5, 6, 7,    0, 1, 2, 3,
                    12,13,14,15,   8, 9,10,11,
                    4, 5, 6, 7,    0, 1, 2, 3 }, 0);
            ret.rearrange(shuffle, shuffle.laneIsValid());
            return ret;
        }

        void write8(byte[] out, int offset, IntVector v) {
            // var shuffle = VectorShuffle.fromArray(SPECIES_256, new int[]{0x0C0D0E0F, 0x08090A0B, 0x04050607, 0x00010203, 0x0C0D0E0F, 0x08090A0B, 0x04050607, 0x00010203 }, 0);
            var shuffle = VectorShuffle.fromArray(SPECIES_256, new int[]{
                    12,13,14,15,   8, 9,10,11,
                    4, 5, 6, 7,    0, 1, 2, 3,
                    12,13,14,15,   8, 9,10,11,
                    4, 5, 6, 7,    0, 1, 2, 3 }, 0);
            v.rearrange(shuffle, shuffle.laneIsValid());
            System.out.println("v: " + Arrays.toString(v.toArray()));
            byte[] arr = new byte[256];
            v.intoByteArray(arr, 0, ByteOrder.LITTLE_ENDIAN);
            System.out.println("arr: " + Arrays.toString(arr));
            System.arraycopy(arr, 0, out, 0, 256);
            /*
            out[0 + offset] = (char) v.lane(7);
            out[32 + offset] = (char) v.lane(6);
            out[64 + offset] = (char) v.lane(5);
            out[96 + offset] = (char) v.lane(4);
            out[128 + offset] = (char) v.lane(3);
            out[160 + offset] = (char) v.lane(2);
            out[192 + offset] = (char) v.lane(1);
            out[224 + offset] = (char) v.lane(0);
             */
        }

        void round(IntVector a, IntVector b, IntVector c, IntVector d, IntVector e, IntVector f, IntVector g, IntVector h, IntVector k) {
            IntVector t1 = add(h, Sigma1(e), ch(e, f, g), k);
            System.out.print("t1: ");
            System.out.print(t1.lane(0) + ",");
            System.out.print(t1.lane(1) + ",");
            System.out.print(t1.lane(2) + ",");
            System.out.print(t1.lane(3) + ",");
            System.out.print(t1.lane(4) + ",");
            System.out.print(t1.lane(5) + ",");
            System.out.print(t1.lane(6) + ",");
            System.out.println(t1.lane(7));
            IntVector t2 = add(Sigma0(a), maj(a, b, c));
            this.d = add(d, t1);
            this.h = add(t1, t2);
        }

        /**
         * Takes 256-bit (32 bytes) chunks.
         *
         * @param in
         * @return
         */
        public void transform_8way(byte[] in, byte[] out) {
            System.out.println("transform_8way:\n");
            System.out.println("in: " + bytesToHex(in));
            IntVector a = IntVector.broadcast(SPECIES_256, INITIAL_HASHES[0]);
            IntVector b = IntVector.broadcast(SPECIES_256, INITIAL_HASHES[1]);
            IntVector c = IntVector.broadcast(SPECIES_256, INITIAL_HASHES[2]);
            d = IntVector.broadcast(SPECIES_256, INITIAL_HASHES[3]);
            IntVector e = IntVector.broadcast(SPECIES_256, INITIAL_HASHES[4]);
            IntVector f = IntVector.broadcast(SPECIES_256, INITIAL_HASHES[5]);
            IntVector g = IntVector.broadcast(SPECIES_256, INITIAL_HASHES[6]);
            h = IntVector.broadcast(SPECIES_256, INITIAL_HASHES[7]);

            IntVector w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15;

            byte[] buffer = new byte[8];
            System.arraycopy(in, 0, buffer, 0, 8);
            w0 = read8(buffer);
            round(a, b, c, d, e, f, g, h, add(IntVector.broadcast(SPECIES_256, 0x428a2f98), w0));

            System.arraycopy(in, 8, buffer, 0, 8);
            w1 = read8(buffer);
            round(h, a, b, c, d, e, f, g, add(IntVector.broadcast(SPECIES_256, 0x71374491), w1));

            System.arraycopy(in, 16, buffer, 0, 8);
            w2 = read8(buffer);
            round(g, h, a, b, c, d, e, f, add(IntVector.broadcast(SPECIES_256, 0xb5c0fbcf), w2));

            System.arraycopy(in, 24, buffer, 0, 8);
            w3 = read8(buffer);
            round(f, g, h, a, b, c, d, e, add(IntVector.broadcast(SPECIES_256, 0xe9b5dba5), w3));

            System.arraycopy(in, 32, buffer, 0, 8);
            w4 = read8(buffer);
            round(e, f, g, h, a, b, c, d, add(IntVector.broadcast(SPECIES_256, 0x3956c25b), w4));

            System.arraycopy(in, 40, buffer, 0, 8);
            w5 = read8(buffer);
            round(d, e, f, g, h, a, b, c, add(IntVector.broadcast(SPECIES_256, 0x59f111f1), w5));

            System.arraycopy(in, 48, buffer, 0, 8);
            w6 = read8(buffer);
            round(c, d, e, f, g, h, a, b, add(IntVector.broadcast(SPECIES_256, 0x923f82a4), w6));

            System.arraycopy(in, 56, buffer, 0, 8);
            w7 = read8(buffer);
            round(b, c, d, e, f, g, h, a, add(IntVector.broadcast(SPECIES_256, 0xab1c5ed5), w7));

            System.arraycopy(in, 64, buffer, 0, 8);
            w8 = read8(buffer);
            round(a, b, c, d, e, f, g, h, add(IntVector.broadcast(SPECIES_256, 0xd807aa98), w8));

            System.arraycopy(in, 72, buffer, 0, 8);
            w9 = read8(buffer);
            round(h, a, b, c, d, e, f, g, add(IntVector.broadcast(SPECIES_256, 0x12835b01), w9));

            System.arraycopy(in, 80, buffer, 0, 8);
            w10 = read8(buffer);
            round(g, h, a, b, c, d, e, f, add(IntVector.broadcast(SPECIES_256, 0x243185be), w10));

            System.arraycopy(in, 88, buffer, 0, 8);
            w11 = read8(buffer);
            round(f, g, h, a, b, c, d, e, add(IntVector.broadcast(SPECIES_256, 0x550c7dc3), w11));

            System.arraycopy(in, 96, buffer, 0, 8);
            w12 = read8(buffer);
            round(e, f, g, h, a, b, c, d, add(IntVector.broadcast(SPECIES_256, 0x72be5d74), w12));

            System.arraycopy(in, 104, buffer, 0, 8);
            w13 = read8(buffer);
            round(d, e, f, g, h, a, b, c, add(IntVector.broadcast(SPECIES_256, 0x80deb1fe), w13));

            System.arraycopy(in, 112, buffer, 0, 8);
            w14 = read8(buffer);
            round(c, d, e, f, g, h, a, b, add(IntVector.broadcast(SPECIES_256, 0x9bdc06a7), w14));

            System.arraycopy(in, 120, buffer, 0, 8);
            w15 = read8(buffer);
            round(b, c, d, e, f, g, h, a, add(IntVector.broadcast(SPECIES_256, 0xc19bf174), w15));

            round(a, b, c, d, e, f, g, h, add(IntVector.broadcast(SPECIES_256, 0xe49b69c1), inc(w0, sigma1(w14), w9, sigma0(w1))));
            round(h, a, b, c, d, e, f, g, add(IntVector.broadcast(SPECIES_256, 0xefbe4786), inc(w1, sigma1(w15), w10, sigma0(w2))));
            round(g, h, a, b, c, d, e, f, add(IntVector.broadcast(SPECIES_256, 0x0fc19dc6), inc(w2, sigma1(w0), w11, sigma0(w3))));
            round(f, g, h, a, b, c, d, e, add(IntVector.broadcast(SPECIES_256, 0x240ca1cc), inc(w3, sigma1(w1), w12, sigma0(w4))));
            round(e, f, g, h, a, b, c, d, add(IntVector.broadcast(SPECIES_256, 0x2de92c6f), inc(w4, sigma1(w2), w13, sigma0(w5))));
            round(d, e, f, g, h, a, b, c, add(IntVector.broadcast(SPECIES_256, 0x4a7484aa), inc(w5, sigma1(w3), w14, sigma0(w6))));
            round(c, d, e, f, g, h, a, b, add(IntVector.broadcast(SPECIES_256, 0x5cb0a9dc), inc(w6, sigma1(w4), w15, sigma0(w7))));
            round(b, c, d, e, f, g, h, a, add(IntVector.broadcast(SPECIES_256, 0x76f988da), inc(w7, sigma1(w5), w0, sigma0(w8))));
            round(a, b, c, d, e, f, g, h, add(IntVector.broadcast(SPECIES_256, 0x983e5152), inc(w8, sigma1(w6), w1, sigma0(w9))));
            round(h, a, b, c, d, e, f, g, add(IntVector.broadcast(SPECIES_256, 0xa831c66d), inc(w9, sigma1(w7), w2, sigma0(w10))));
            round(g, h, a, b, c, d, e, f, add(IntVector.broadcast(SPECIES_256, 0xb00327c8), inc(w10, sigma1(w8), w3, sigma0(w11))));
            round(f, g, h, a, b, c, d, e, add(IntVector.broadcast(SPECIES_256, 0xbf597fc7), inc(w11, sigma1(w9), w4, sigma0(w12))));
            round(e, f, g, h, a, b, c, d, add(IntVector.broadcast(SPECIES_256, 0xc6e00bf3), inc(w12, sigma1(w10), w5, sigma0(w13))));
            round(d, e, f, g, h, a, b, c, add(IntVector.broadcast(SPECIES_256, 0xd5a79147), inc(w13, sigma1(w11), w6, sigma0(w14))));
            round(c, d, e, f, g, h, a, b, add(IntVector.broadcast(SPECIES_256, 0x06ca6351), inc(w14, sigma1(w12), w7, sigma0(w15))));
            round(b, c, d, e, f, g, h, a, add(IntVector.broadcast(SPECIES_256, 0x14292967), inc(w15, sigma1(w13), w8, sigma0(w0))));
            round(a, b, c, d, e, f, g, h, add(IntVector.broadcast(SPECIES_256, 0x27b70a85), inc(w0, sigma1(w14), w9, sigma0(w1))));
            round(h, a, b, c, d, e, f, g, add(IntVector.broadcast(SPECIES_256, 0x2e1b2138), inc(w1, sigma1(w15), w10, sigma0(w2))));
            round(g, h, a, b, c, d, e, f, add(IntVector.broadcast(SPECIES_256, 0x4d2c6dfc), inc(w2, sigma1(w0), w11, sigma0(w3))));
            round(f, g, h, a, b, c, d, e, add(IntVector.broadcast(SPECIES_256, 0x53380d13), inc(w3, sigma1(w1), w12, sigma0(w4))));
            round(e, f, g, h, a, b, c, d, add(IntVector.broadcast(SPECIES_256, 0x650a7354), inc(w4, sigma1(w2), w13, sigma0(w5))));
            round(d, e, f, g, h, a, b, c, add(IntVector.broadcast(SPECIES_256, 0x766a0abb), inc(w5, sigma1(w3), w14, sigma0(w6))));
            round(c, d, e, f, g, h, a, b, add(IntVector.broadcast(SPECIES_256, 0x81c2c92e), inc(w6, sigma1(w4), w15, sigma0(w7))));
            round(b, c, d, e, f, g, h, a, add(IntVector.broadcast(SPECIES_256, 0x92722c85), inc(w7, sigma1(w5), w0, sigma0(w8))));
            round(a, b, c, d, e, f, g, h, add(IntVector.broadcast(SPECIES_256, 0xa2bfe8a1), inc(w8, sigma1(w6), w1, sigma0(w9))));
            round(h, a, b, c, d, e, f, g, add(IntVector.broadcast(SPECIES_256, 0xa81a664b), inc(w9, sigma1(w7), w2, sigma0(w10))));
            round(g, h, a, b, c, d, e, f, add(IntVector.broadcast(SPECIES_256, 0xc24b8b70), inc(w10, sigma1(w8), w3, sigma0(w11))));
            round(f, g, h, a, b, c, d, e, add(IntVector.broadcast(SPECIES_256, 0xc76c51a3), inc(w11, sigma1(w9), w4, sigma0(w12))));
            round(e, f, g, h, a, b, c, d, add(IntVector.broadcast(SPECIES_256, 0xd192e819), inc(w12, sigma1(w10), w5, sigma0(w13))));
            round(d, e, f, g, h, a, b, c, add(IntVector.broadcast(SPECIES_256, 0xd6990624), inc(w13, sigma1(w11), w6, sigma0(w14))));
            round(c, d, e, f, g, h, a, b, add(IntVector.broadcast(SPECIES_256, 0xf40e3585), inc(w14, sigma1(w12), w7, sigma0(w15))));
            round(b, c, d, e, f, g, h, a, add(IntVector.broadcast(SPECIES_256, 0x106aa070), inc(w15, sigma1(w13), w8, sigma0(w0))));
            round(a, b, c, d, e, f, g, h, add(IntVector.broadcast(SPECIES_256, 0x19a4c116), inc(w0, sigma1(w14), w9, sigma0(w1))));
            round(h, a, b, c, d, e, f, g, add(IntVector.broadcast(SPECIES_256, 0x1e376c08), inc(w1, sigma1(w15), w10, sigma0(w2))));
            round(g, h, a, b, c, d, e, f, add(IntVector.broadcast(SPECIES_256, 0x2748774c), inc(w2, sigma1(w0), w11, sigma0(w3))));
            round(f, g, h, a, b, c, d, e, add(IntVector.broadcast(SPECIES_256, 0x34b0bcb5), inc(w3, sigma1(w1), w12, sigma0(w4))));
            round(e, f, g, h, a, b, c, d, add(IntVector.broadcast(SPECIES_256, 0x391c0cb3), inc(w4, sigma1(w2), w13, sigma0(w5))));
            round(d, e, f, g, h, a, b, c, add(IntVector.broadcast(SPECIES_256, 0x4ed8aa4a), inc(w5, sigma1(w3), w14, sigma0(w6))));
            round(c, d, e, f, g, h, a, b, add(IntVector.broadcast(SPECIES_256, 0x5b9cca4f), inc(w6, sigma1(w4), w15, sigma0(w7))));
            round(b, c, d, e, f, g, h, a, add(IntVector.broadcast(SPECIES_256, 0x682e6ff3), inc(w7, sigma1(w5), w0, sigma0(w8))));
            round(a, b, c, d, e, f, g, h, add(IntVector.broadcast(SPECIES_256, 0x748f82ee), inc(w8, sigma1(w6), w1, sigma0(w9))));
            round(h, a, b, c, d, e, f, g, add(IntVector.broadcast(SPECIES_256, 0x78a5636f), inc(w9, sigma1(w7), w2, sigma0(w10))));
            round(g, h, a, b, c, d, e, f, add(IntVector.broadcast(SPECIES_256, 0x84c87814), inc(w10, sigma1(w8), w3, sigma0(w11))));
            round(f, g, h, a, b, c, d, e, add(IntVector.broadcast(SPECIES_256, 0x8cc70208), inc(w11, sigma1(w9), w4, sigma0(w12))));
            round(e, f, g, h, a, b, c, d, add(IntVector.broadcast(SPECIES_256, 0x90befffa), inc(w12, sigma1(w10), w5, sigma0(w13))));
            round(d, e, f, g, h, a, b, c, add(IntVector.broadcast(SPECIES_256, 0xa4506ceb), inc(w13, sigma1(w11), w6, sigma0(w14))));
            round(c, d, e, f, g, h, a, b, add(IntVector.broadcast(SPECIES_256, 0xbef9a3f7), inc(w14, sigma1(w12), w7, sigma0(w15))));
            round(b, c, d, e, f, g, h, a, add(IntVector.broadcast(SPECIES_256, 0xc67178f2), inc(w15, sigma1(w13), w8, sigma0(w0))));

            a = add(a, IntVector.broadcast(SPECIES_256, INITIAL_HASHES[0]));
            b = add(b, IntVector.broadcast(SPECIES_256, INITIAL_HASHES[1]));
            c = add(c, IntVector.broadcast(SPECIES_256, INITIAL_HASHES[2]));
            d = add(d, IntVector.broadcast(SPECIES_256, INITIAL_HASHES[3]));
            e = add(e, IntVector.broadcast(SPECIES_256, INITIAL_HASHES[4]));
            f = add(f, IntVector.broadcast(SPECIES_256, INITIAL_HASHES[5]));
            g = add(g, IntVector.broadcast(SPECIES_256, INITIAL_HASHES[6]));
            h = add(h, IntVector.broadcast(SPECIES_256, INITIAL_HASHES[7]));

            System.out.println("a: " + Arrays.toString(a.toArray()));
            System.out.println("b: " + Arrays.toString(b.toArray()));
            System.out.println("c: " + Arrays.toString(c.toArray()));
            System.out.println("d: " + Arrays.toString(d.toArray()));
            System.out.println("e: " + Arrays.toString(e.toArray()));
            System.out.println("f: " + Arrays.toString(f.toArray()));
            System.out.println("g: " + Arrays.toString(g.toArray()));
            System.out.println("h: " + Arrays.toString(h.toArray()));
            write8(out, 0, add(a, IntVector.broadcast(SPECIES_256, INITIAL_HASHES[0])));
            write8(out, 4, add(b, IntVector.broadcast(SPECIES_256, INITIAL_HASHES[1])));
            write8(out, 8, add(c, IntVector.broadcast(SPECIES_256, INITIAL_HASHES[2])));
            write8(out, 12, add(d, IntVector.broadcast(SPECIES_256, INITIAL_HASHES[3])));
            write8(out, 16, add(e, IntVector.broadcast(SPECIES_256, INITIAL_HASHES[4])));
            write8(out, 20, add(f, IntVector.broadcast(SPECIES_256, INITIAL_HASHES[5])));
            write8(out, 24, add(g, IntVector.broadcast(SPECIES_256, INITIAL_HASHES[6])));
            write8(out, 28, add(h, IntVector.broadcast(SPECIES_256, INITIAL_HASHES[7])));
            System.out.println("out: " + Arrays.toString(out));
        }
    }

}