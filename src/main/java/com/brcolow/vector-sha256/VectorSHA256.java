package com.brcolow.vector-sha256;

import jdk.incubator.vector.IntVector;
import jdk.incubator.vector.VectorOperators;
import jdk.incubator.vector.VectorShuffle;
import jdk.incubator.vector.VectorSpecies;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * https://github.com/bitcoin/bitcoin/blob/7fcf53f7b4524572d1d0c9a5fdc388e87eb02416/src/crypto/sha256.h
 * https://github.com/bitcoin/bitcoin/blob/7fcf53f7b4524572d1d0c9a5fdc388e87eb02416/src/crypto/sha256.cpp
 * https://github.com/bitcoin/bitcoin/blob/7fcf53f7b4524572d1d0c9a5fdc388e87eb02416/src/crypto/sha256_avx2.cpp
 * https://github.com/bcgit/bc-java/blob/bc3b92f1f0e78b82e2584c5fb4b226a13e7f8b3b/core/src/main/java/org/bouncycastle/crypto/digests/SHA256Digest.java
 * https://github.com/bcgit/bc-java/blob/bc3b92f1f0e78b82e2584c5fb4b226a13e7f8b3b/core/src/main/java/org/bouncycastle/crypto/digests/GeneralDigest.java
 * https://github.com/openjdk/jdk/blob/739769c8fc4b496f08a92225a12d07414537b6c0/src/java.base/share/classes/sun/security/provider/SHA2.java#L250
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
        System.out.println("data.length: " + data.length);
        int[] out = new int[256];
        Sha256Digest sha256Digest = new Sha256Digest();
        sha256Digest.transform_8way("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxy".getBytes(StandardCharsets.UTF_8), out);
        //sha256Digest.transform_8way(data, out);
        System.out.println("out: " + Arrays.toString(out));
    }

    public static class Sha256Digest {
        private IntVector d;
        private IntVector h;
        private int[] state;
        byte[] buffer;
        private int bufOfs;
        private final int blockSize = 64;
        private final int digestLength = 32;
        long bytesProcessed;

        private static final int[] INITIAL_HASHES = {
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        };

        public Sha256Digest() {
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
                int n = Math.min(len, blockSize - bufOfs);
                System.arraycopy(in, inOff, buffer, bufOfs, n);
                bufOfs += n;
                inOff += n;
                len -= n;
                if (bufOfs >= blockSize) {
                    // compress completed block now
                    int[] out = new int[8];
                    transform_8way(buffer, out);
                    bufOfs = 0;
                }
                if (len >= blockSize) {
                    int limit = inOff + len;
                    for (; inOff <= limit; inOff += blockSize) {
                        int[] out = new int[8];
                        transform_8way(in, out);
                    }
                    len = limit - inOff;
                }
                // copy remainder to buffer
                if (len > 0) {
                    System.arraycopy(in, inOff, buffer, 0, len);
                    bufOfs = len;
                }
            }
        }

        public void finish() {
            // TODO
        }

        private void process256Bits(IntVector in, int offset) {
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
            var shuffle = VectorShuffle.fromArray(SPECIES_256, new int[]{0x0C0D0E0F, 0x08090A0B, 0x04050607, 0x00010203, 0x0C0D0E0F, 0x08090A0B, 0x04050607, 0x00010203 }, 0);
            ret.rearrange(shuffle, shuffle.laneIsValid());
            return ret;
        }

        void write8(int[] out, int offset, IntVector v) {
            var shuffle = VectorShuffle.fromArray(SPECIES_256, new int[]{0x0C0D0E0F, 0x08090A0B, 0x04050607, 0x00010203, 0x0C0D0E0F, 0x08090A0B, 0x04050607, 0x00010203 }, 0);
            v.rearrange(shuffle, shuffle.laneIsValid());
            System.out.println("v: " + Arrays.toString(v.toArray()));
            out[0 + offset] = (char) v.lane(7);
            out[32 + offset] = (char) v.lane(6);
            out[64 + offset] = (char) v.lane(5);
            out[96 + offset] = (char) v.lane(4);
            out[128 + offset] = (char) v.lane(3);
            out[160 + offset] = (char) v.lane(2);
            out[192 + offset] = (char) v.lane(1);
            out[224 + offset] = (char) v.lane(0);
        }

        void round(IntVector a, IntVector b, IntVector c, IntVector d, IntVector e, IntVector f, IntVector g, IntVector h, IntVector k) {
            IntVector t1 = add(h, Sigma1(e), ch(e, f, g), k);
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
        public void transform_8way(byte[] in, int[] out) {
            // Transform 1
            IntVector a = IntVector.broadcast(SPECIES_256, 0x6a09e667);
            IntVector b = IntVector.broadcast(SPECIES_256, 0xbb67ae85);
            IntVector c = IntVector.broadcast(SPECIES_256, 0x3c6ef372);
            d = IntVector.broadcast(SPECIES_256, 0xa54ff53a);
            IntVector e = IntVector.broadcast(SPECIES_256, 0x510e527f);
            IntVector f = IntVector.broadcast(SPECIES_256, 0x9b05688c);
            IntVector g = IntVector.broadcast(SPECIES_256, 0x1f83d9ab);
            h = IntVector.broadcast(SPECIES_256, 0x5be0cd19);

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

            a = add(a, IntVector.broadcast(SPECIES_256, 0x6a09e667));
            b = add(b, IntVector.broadcast(SPECIES_256, 0xbb67ae85));
            c = add(c, IntVector.broadcast(SPECIES_256, 0x3c6ef372));
            d = add(d, IntVector.broadcast(SPECIES_256, 0xa54ff53a));
            e = add(e, IntVector.broadcast(SPECIES_256, 0x510e527f));
            f = add(f, IntVector.broadcast(SPECIES_256, 0x9b05688c));
            g = add(g, IntVector.broadcast(SPECIES_256, 0x1f83d9ab));
            h = add(h, IntVector.broadcast(SPECIES_256, 0x5be0cd19));

            //    __m256i t0 = a, t1 = b, t2 = c, t3 = d, t4 = e, t5 = f, t6 = g, t7 = h;
            IntVector t0 = IntVector.fromArray(SPECIES_256, a.toArray(), 0);
            IntVector t1 = IntVector.fromArray(SPECIES_256, b.toArray(), 0);
            IntVector t2 = IntVector.fromArray(SPECIES_256, c.toArray(), 0);
            IntVector t3 = IntVector.fromArray(SPECIES_256, d.toArray(), 0);
            IntVector t4 = IntVector.fromArray(SPECIES_256, e.toArray(), 0);
            IntVector t5 = IntVector.fromArray(SPECIES_256, f.toArray(), 0);
            IntVector t6 = IntVector.fromArray(SPECIES_256, g.toArray(), 0);
            IntVector t7 = IntVector.fromArray(SPECIES_256, h.toArray(), 0);

            // Transform 2
            round(a, b, c, d, e, f, g, h, IntVector.broadcast(SPECIES_256, 0xc28a2f98));
            round(h, a, b, c, d, e, f, g, IntVector.broadcast(SPECIES_256, 0x71374491));
            round(g, h, a, b, c, d, e, f, IntVector.broadcast(SPECIES_256, 0xb5c0fbcf));
            round(f, g, h, a, b, c, d, e, IntVector.broadcast(SPECIES_256, 0xe9b5dba5));
            round(e, f, g, h, a, b, c, d, IntVector.broadcast(SPECIES_256, 0x3956c25b));
            round(d, e, f, g, h, a, b, c, IntVector.broadcast(SPECIES_256, 0x59f111f1));
            round(c, d, e, f, g, h, a, b, IntVector.broadcast(SPECIES_256, 0x923f82a4));
            round(b, c, d, e, f, g, h, a, IntVector.broadcast(SPECIES_256, 0xab1c5ed5));
            round(a, b, c, d, e, f, g, h, IntVector.broadcast(SPECIES_256, 0xd807aa98));
            round(h, a, b, c, d, e, f, g, IntVector.broadcast(SPECIES_256, 0x12835b01));
            round(g, h, a, b, c, d, e, f, IntVector.broadcast(SPECIES_256, 0x243185be));
            round(f, g, h, a, b, c, d, e, IntVector.broadcast(SPECIES_256, 0x550c7dc3));
            round(e, f, g, h, a, b, c, d, IntVector.broadcast(SPECIES_256, 0x72be5d74));
            round(d, e, f, g, h, a, b, c, IntVector.broadcast(SPECIES_256, 0x80deb1fe));
            round(c, d, e, f, g, h, a, b, IntVector.broadcast(SPECIES_256, 0x9bdc06a7));
            round(b, c, d, e, f, g, h, a, IntVector.broadcast(SPECIES_256, 0xc19bf374));
            round(a, b, c, d, e, f, g, h, IntVector.broadcast(SPECIES_256, 0x649b69c1));
            round(h, a, b, c, d, e, f, g, IntVector.broadcast(SPECIES_256, 0xf0fe4786));
            round(g, h, a, b, c, d, e, f, IntVector.broadcast(SPECIES_256, 0x0fe1edc6));
            round(f, g, h, a, b, c, d, e, IntVector.broadcast(SPECIES_256, 0x240cf254));
            round(e, f, g, h, a, b, c, d, IntVector.broadcast(SPECIES_256, 0x4fe9346f));
            round(d, e, f, g, h, a, b, c, IntVector.broadcast(SPECIES_256, 0x6cc984be));
            round(c, d, e, f, g, h, a, b, IntVector.broadcast(SPECIES_256, 0x61b9411e));
            round(b, c, d, e, f, g, h, a, IntVector.broadcast(SPECIES_256, 0x16f988fa));
            round(a, b, c, d, e, f, g, h, IntVector.broadcast(SPECIES_256, 0xf2c65152));
            round(h, a, b, c, d, e, f, g, IntVector.broadcast(SPECIES_256, 0xa88e5a6d));
            round(g, h, a, b, c, d, e, f, IntVector.broadcast(SPECIES_256, 0xb019fc65));
            round(f, g, h, a, b, c, d, e, IntVector.broadcast(SPECIES_256, 0xb9d99ec7));
            round(e, f, g, h, a, b, c, d, IntVector.broadcast(SPECIES_256, 0x9a1231c3));
            round(d, e, f, g, h, a, b, c, IntVector.broadcast(SPECIES_256, 0xe70eeaa0));
            round(c, d, e, f, g, h, a, b, IntVector.broadcast(SPECIES_256, 0xfdb1232b));
            round(b, c, d, e, f, g, h, a, IntVector.broadcast(SPECIES_256, 0xc7353eb0));
            round(a, b, c, d, e, f, g, h, IntVector.broadcast(SPECIES_256, 0x3069bad5));
            round(h, a, b, c, d, e, f, g, IntVector.broadcast(SPECIES_256, 0xcb976d5f));
            round(g, h, a, b, c, d, e, f, IntVector.broadcast(SPECIES_256, 0x5a0f118f));
            round(f, g, h, a, b, c, d, e, IntVector.broadcast(SPECIES_256, 0xdc1eeefd));
            round(e, f, g, h, a, b, c, d, IntVector.broadcast(SPECIES_256, 0x0a35b689));
            round(d, e, f, g, h, a, b, c, IntVector.broadcast(SPECIES_256, 0xde0b7a04));
            round(c, d, e, f, g, h, a, b, IntVector.broadcast(SPECIES_256, 0x58f4ca9d));
            round(b, c, d, e, f, g, h, a, IntVector.broadcast(SPECIES_256, 0xe15d5b16));
            round(a, b, c, d, e, f, g, h, IntVector.broadcast(SPECIES_256, 0x007f3e86));
            round(h, a, b, c, d, e, f, g, IntVector.broadcast(SPECIES_256, 0x37088980));
            round(g, h, a, b, c, d, e, f, IntVector.broadcast(SPECIES_256, 0xa507ea32));
            round(f, g, h, a, b, c, d, e, IntVector.broadcast(SPECIES_256, 0x6fab9537));
            round(e, f, g, h, a, b, c, d, IntVector.broadcast(SPECIES_256, 0x17406110));
            round(d, e, f, g, h, a, b, c, IntVector.broadcast(SPECIES_256, 0x0d8cd6f1));
            round(c, d, e, f, g, h, a, b, IntVector.broadcast(SPECIES_256, 0xcdaa3b6d));
            round(b, c, d, e, f, g, h, a, IntVector.broadcast(SPECIES_256, 0xc0bbbe37));
            round(a, b, c, d, e, f, g, h, IntVector.broadcast(SPECIES_256, 0x83613bda));
            round(h, a, b, c, d, e, f, g, IntVector.broadcast(SPECIES_256, 0xdb48a363));
            round(g, h, a, b, c, d, e, f, IntVector.broadcast(SPECIES_256, 0x0b02e931));
            round(f, g, h, a, b, c, d, e, IntVector.broadcast(SPECIES_256, 0x6fd15ca7));
            round(e, f, g, h, a, b, c, d, IntVector.broadcast(SPECIES_256, 0x521afaca));
            round(d, e, f, g, h, a, b, c, IntVector.broadcast(SPECIES_256, 0x31338431));
            round(c, d, e, f, g, h, a, b, IntVector.broadcast(SPECIES_256, 0x6ed41a95));
            round(b, c, d, e, f, g, h, a, IntVector.broadcast(SPECIES_256, 0x6d437890));
            round(a, b, c, d, e, f, g, h, IntVector.broadcast(SPECIES_256, 0xc39c91f2));
            round(h, a, b, c, d, e, f, g, IntVector.broadcast(SPECIES_256, 0x9eccabbd));
            round(g, h, a, b, c, d, e, f, IntVector.broadcast(SPECIES_256, 0xb5c9a0e6));
            round(f, g, h, a, b, c, d, e, IntVector.broadcast(SPECIES_256, 0x532fb63c));
            round(e, f, g, h, a, b, c, d, IntVector.broadcast(SPECIES_256, 0xd2c741c6));
            round(d, e, f, g, h, a, b, c, IntVector.broadcast(SPECIES_256, 0x07237ea3));
            round(c, d, e, f, g, h, a, b, IntVector.broadcast(SPECIES_256, 0xa4954b68));
            round(b, c, d, e, f, g, h, a, IntVector.broadcast(SPECIES_256, 0x4c191d76));

            w0 = add(t0, a);
            w1 = add(t1, b);
            w2 = add(t2, c);
            w3 = add(t3, d);
            w4 = add(t4, e);
            w5 = add(t5, f);
            w6 = add(t6, g);
            w7 = add(t7, h);

            // Transform 3
            a = IntVector.broadcast(SPECIES_256, 0x6a09e667);
            b = IntVector.broadcast(SPECIES_256, 0xbb67ae85);
            c = IntVector.broadcast(SPECIES_256, 0x3c6ef372);
            d = IntVector.broadcast(SPECIES_256, 0xa54ff53a);
            e = IntVector.broadcast(SPECIES_256, 0x510e527f);
            f = IntVector.broadcast(SPECIES_256, 0x9b05688c);
            g = IntVector.broadcast(SPECIES_256, 0x1f83d9ab);
            h = IntVector.broadcast(SPECIES_256, 0x5be0cd19);

            round(a, b, c, d, e, f, g, h, add(IntVector.broadcast(SPECIES_256, 0x428a2f98), w0));
            round(h, a, b, c, d, e, f, g, add(IntVector.broadcast(SPECIES_256, 0x71374491), w1));
            round(g, h, a, b, c, d, e, f, add(IntVector.broadcast(SPECIES_256, 0xb5c0fbcf), w2));
            round(f, g, h, a, b, c, d, e, add(IntVector.broadcast(SPECIES_256, 0xe9b5dba5), w3));
            round(e, f, g, h, a, b, c, d, add(IntVector.broadcast(SPECIES_256, 0x3956c25b), w4));
            round(d, e, f, g, h, a, b, c, add(IntVector.broadcast(SPECIES_256, 0x59f111f1), w5));
            round(c, d, e, f, g, h, a, b, add(IntVector.broadcast(SPECIES_256, 0x923f82a4), w6));
            round(b, c, d, e, f, g, h, a, add(IntVector.broadcast(SPECIES_256, 0xab1c5ed5), w7));
            round(a, b, c, d, e, f, g, h, IntVector.broadcast(SPECIES_256, 0x5807aa98));
            round(h, a, b, c, d, e, f, g, IntVector.broadcast(SPECIES_256, 0x12835b01));
            round(g, h, a, b, c, d, e, f, IntVector.broadcast(SPECIES_256, 0x243185be));
            round(f, g, h, a, b, c, d, e, IntVector.broadcast(SPECIES_256, 0x550c7dc3));
            round(e, f, g, h, a, b, c, d, IntVector.broadcast(SPECIES_256, 0x72be5d74));
            round(d, e, f, g, h, a, b, c, IntVector.broadcast(SPECIES_256, 0x80deb1fe));
            round(c, d, e, f, g, h, a, b, IntVector.broadcast(SPECIES_256, 0x9bdc06a7));
            round(b, c, d, e, f, g, h, a, IntVector.broadcast(SPECIES_256, 0xc19bf274));
            round(a, b, c, d, e, f, g, h, add(IntVector.broadcast(SPECIES_256, 0xe49b69c1), inc(w0, sigma0(w1))));
            round(h, a, b, c, d, e, f, g, add(IntVector.broadcast(SPECIES_256, 0xefbe4786), inc(w1, IntVector.broadcast(SPECIES_256, 0xa00000), sigma0(w2))));
            round(g, h, a, b, c, d, e, f, add(IntVector.broadcast(SPECIES_256, 0x0fc19dc6), inc(w2, sigma1(w0), sigma0(w3))));
            round(f, g, h, a, b, c, d, e, add(IntVector.broadcast(SPECIES_256, 0x240ca1cc), inc(w3, sigma1(w1), sigma0(w4))));
            round(e, f, g, h, a, b, c, d, add(IntVector.broadcast(SPECIES_256, 0x2de92c6f), inc(w4, sigma1(w2), sigma0(w5))));
            round(d, e, f, g, h, a, b, c, add(IntVector.broadcast(SPECIES_256, 0x4a7484aa), inc(w5, sigma1(w3), sigma0(w6))));
            round(c, d, e, f, g, h, a, b, add(IntVector.broadcast(SPECIES_256, 0x5cb0a9dc), inc(w6, sigma1(w4), IntVector.broadcast(SPECIES_256, 0x100), sigma0(w7))));
            round(b, c, d, e, f, g, h, a, add(IntVector.broadcast(SPECIES_256, 0x76f988da), inc(w7, sigma1(w5), w0, IntVector.broadcast(SPECIES_256, 0x11002000))));
            round(a, b, c, d, e, f, g, h, add(IntVector.broadcast(SPECIES_256, 0x983e5152), w8 = add(IntVector.broadcast(SPECIES_256, 0x80000000), sigma1(w6), w1)));
            round(h, a, b, c, d, e, f, g, add(IntVector.broadcast(SPECIES_256, 0xa831c66d), w9 = add(sigma1(w7), w2)));
            round(g, h, a, b, c, d, e, f, add(IntVector.broadcast(SPECIES_256, 0xb00327c8), w10 = add(sigma1(w8), w3)));
            round(f, g, h, a, b, c, d, e, add(IntVector.broadcast(SPECIES_256, 0xbf597fc7), w11 = add(sigma1(w9), w4)));
            round(e, f, g, h, a, b, c, d, add(IntVector.broadcast(SPECIES_256, 0xc6e00bf3), w12 = add(sigma1(w10), w5)));
            round(d, e, f, g, h, a, b, c, add(IntVector.broadcast(SPECIES_256, 0xd5a79147), w13 = add(sigma1(w11), w6)));
            round(c, d, e, f, g, h, a, b, add(IntVector.broadcast(SPECIES_256, 0x06ca6351), w14 = add(sigma1(w12), w7, IntVector.broadcast(SPECIES_256, 0x400022))));
            round(b, c, d, e, f, g, h, a, add(IntVector.broadcast(SPECIES_256, 0x14292967), w15 = add(IntVector.broadcast(SPECIES_256, 0x100), sigma1(w13), w8, sigma0(w0))));
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
            round(c, d, e, f, g, h, a, b, add(IntVector.broadcast(SPECIES_256, 0xbef9a3f7), w14, sigma1(w12), w7, sigma0(w15)));
            round(b, c, d, e, f, g, h, a, add(IntVector.broadcast(SPECIES_256, 0xc67178f2), w15, sigma1(w13), w8, sigma0(w0)));

            System.out.println("a: " + Arrays.toString(a.toArray()));
            System.out.println("b: " + Arrays.toString(b.toArray()));
            System.out.println("c: " + Arrays.toString(c.toArray()));
            System.out.println("d: " + Arrays.toString(d.toArray()));
            System.out.println("e: " + Arrays.toString(e.toArray()));
            System.out.println("f: " + Arrays.toString(f.toArray()));
            System.out.println("g: " + Arrays.toString(g.toArray()));
            System.out.println("h: " + Arrays.toString(h.toArray()));
            write8(out, 0, add(a, IntVector.broadcast(SPECIES_256, 0x6a09e667)));
            write8(out, 4, add(b, IntVector.broadcast(SPECIES_256, 0xbb67ae85)));
            write8(out, 8, add(c, IntVector.broadcast(SPECIES_256, 0x3c6ef372)));
            write8(out, 12, add(d, IntVector.broadcast(SPECIES_256, 0xa54ff53a)));
            write8(out, 16, add(e, IntVector.broadcast(SPECIES_256, 0x510e527f)));
            write8(out, 20, add(f, IntVector.broadcast(SPECIES_256, 0x9b05688c)));
            write8(out, 24, add(g, IntVector.broadcast(SPECIES_256, 0x1f83d9ab)));
            write8(out, 28, add(h, IntVector.broadcast(SPECIES_256, 0x5be0cd19)));
        }
    }

}