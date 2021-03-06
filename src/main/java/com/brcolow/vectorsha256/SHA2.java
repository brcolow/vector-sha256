/*
 * Copyright (c) 2003, 2020, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */
package com.brcolow.vectorsha256;

import java.util.Arrays;
import java.util.Objects;

import static com.brcolow.vectorsha256.ByteArrayAccess.b2iBig64;
import static com.brcolow.vectorsha256.ByteArrayAccess.i2bBig;
import static com.brcolow.vectorsha256.ByteArrayAccess.i2bBig4;
import static com.brcolow.vectorsha256.VectorSHA256.Sha256Digest.intToBytesBE;
import static com.brcolow.vectorsha256.VectorSHA256.bytesToHex;

/**
 * This class implements the Secure Hash Algorithm SHA-256 developed by
 * the National Institute of Standards and Technology along with the
 * National Security Agency.
 *
 * <p>It implements java.security.MessageDigestSpi, and can be used
 * through Java Cryptography Architecture (JCA), as a pluggable
 * MessageDigest implementation.
 *
 * @since       1.4.2
 * @author      Valerie Peng
 * @author      Andreas Sterbenz
 */
abstract class SHA2 extends DigestBase {

    private static final int ITERATION = 64;
    // Constants for each round
    private static final int[] ROUND_CONSTS = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    // buffer used by implCompress()
    private int[] W;

    // state of this object
    private int[] H;

    // initial state value. different between SHA-224 and SHA-256
    private final int[] initialHashes;

    /**
     * Creates a new SHA object.
     */
    SHA2(String name, int digestLength, int[] initialHashes) {
        super(name, digestLength, 64);
        this.initialHashes = initialHashes;
        H = new int[8];
        resetHashes();
    }

    /**
     * Resets the buffers and hash value to start a new hash.
     */
    void implReset() {
        resetHashes();
        if (W != null) {
            Arrays.fill(W, 0);
        }
    }

    private void resetHashes() {
        System.arraycopy(initialHashes, 0, H, 0, H.length);
    }

    void implDigest(byte[] out, int ofs) {
        long bitsProcessed = bytesProcessed << 3;

        int index = (int) bytesProcessed & 0x3f;
        int padLen = (index < 56) ? (56 - index) : (120 - index);
        engineUpdate(padding, 0, padLen);

        i2bBig4((int) (bitsProcessed >>> 32), buffer, 56);
        i2bBig4((int) bitsProcessed, buffer, 60);
        implCompress(buffer, 0);

        i2bBig(H, 0, out, ofs, engineGetDigestLength());
    }

    /**
     * Process the current block to update the state variable state.
     */
    void implCompress(byte[] buf, int ofs) {
        int blockNum = ofs / 64;
        System.out.println("Block " + blockNum + " = \"" + bytesToHex(Arrays.copyOfRange(buf, ofs, ofs + 64)) + "\".");
        System.out.println("offset = " + ofs);
        System.out.println("Compressing Block " + blockNum);
        implCompressCheck(buf, ofs);
        implCompress0(buf, ofs);
    }

    private void implCompressCheck(byte[] buf, int ofs) {
        Objects.requireNonNull(buf);

        // Checks similar to those performed by the method 'b2iBig64'
        // are sufficient for the case when the method 'implCompress0' is
        // replaced with a compiler intrinsic.
        if (ofs < 0 || (buf.length - ofs) < 64) {
            throw new ArrayIndexOutOfBoundsException();
        }
    }

    // The method 'implCompressImpl' seems not to use its parameters.
    // The method can, however, be replaced with a compiler intrinsic
    // that operates directly on the array 'buf' (starting from
    // offset 'ofs') and not on array 'W', therefore 'buf' and 'ofs'
    // must be passed as parameter to the method.
    private void implCompress0(byte[] buf, int ofs) {
        if (W == null) {
            W = new int[64];
        }
        b2iBig64(buf, ofs, W);
        // The first 16 ints are from the byte stream, compute the rest of
        // the W[]'s
        for (int t = 16; t < ITERATION; t++) {
            int W_t2 = W[t - 2];
            int W_t15 = W[t - 15];

            // S(x,s) is right rotation of x by s positions:
            //   S(x,s) = (x >>> s) | (x << (32 - s))
            // R(x,s) is right shift of x by s positions:
            //   R(x,s) = (x >>> s)

            // delta0(x) = S(x, 7) ^ S(x, 18) ^ R(x, 3)
            int delta0_W_t15 =
                    ((W_t15 >>> 7) | (W_t15 << 25)) ^
                            ((W_t15 >>> 18) | (W_t15 << 14)) ^
                            (W_t15 >>> 3);

            // delta1(x) = S(x, 17) ^ S(x, 19) ^ R(x, 10)
            int delta1_W_t2 =
                    ((W_t2 >>> 17) | (W_t2 << 15)) ^
                            ((W_t2 >>> 19) | (W_t2 << 13)) ^
                            (W_t2 >>> 10);

            W[t] = delta0_W_t15 + delta1_W_t2 + W[t - 7] + W[t - 16];
        }

        for (int i = 0; i < W.length; i++) {
            System.out.println("[" + i + "]" + W[i]);
        }
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
        for (int i = 0; i < ITERATION; i++) {
            // S(x,s) is right rotation of x by s positions:
            //   S(x,s) = (x >>> s) | (x << (32 - s))

            // sigma0(x) = S(x,2) xor S(x,13) xor S(x,22)
            int sigma0_a =
                    ((a >>> 2) | (a << 30)) ^
                            ((a >>> 13) | (a << 19)) ^
                            ((a >>> 22) | (a << 10));

            // sigma1(x) = S(x,6) xor S(x,11) xor S(x,25)
            int sigma1_e =
                    ((e >>> 6) | (e << 26)) ^
                            ((e >>> 11) | (e << 21)) ^
                            ((e >>> 25) | (e << 7));

            // ch(x,y,z) = (x and y) xor ((complement x) and z)
            int ch_efg = (e & f) ^ ((~e) & g);

            // maj(x,y,z) = (x and y) xor (x and z) xor (y and z)
            int maj_abc = (a & b) ^ (a & c) ^ (b & c);

            int T1 = h + sigma1_e + ch_efg + ROUND_CONSTS[i] + W[i];
            int T2 = sigma0_a + maj_abc;
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
            System.out.println("After round " + i);
            System.out.println("t1 = " + T1);
            System.out.println("t2 = " + T2);
        }

        H[0] += a;
        H[1] += b;
        H[2] += c;
        H[3] += d;
        H[4] += e;
        H[5] += f;
        H[6] += g;
        H[7] += h;
        System.out.println("JDK compress final:");
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
    }

    public Object clone() throws CloneNotSupportedException {
        SHA2 copy = (SHA2) super.clone();
        copy.H = copy.H.clone();
        copy.W = null;
        return copy;
    }

    /**
     * SHA-256 implementation class.
     */
    public static final class SHA256 extends SHA2 {
        private static final int[] INITIAL_HASHES = {
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        };

        public SHA256() {
            super("SHA-256", 32, INITIAL_HASHES);
        }
    }
}