/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this licens
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package org.asterisk.crypto.lowlevel;

import static org.asterisk.crypto.lowlevel.AesPermutation.invAesRound;
import static org.asterisk.crypto.lowlevel.AesPermutation.invAesRoundLast;
import static org.asterisk.crypto.lowlevel.AesPermutation.invMixColumns;

/**
 *
 * @author Sayantan Chakraborty
 */
public abstract sealed class AesDecApi {

    public abstract void decryptBlock(int[] ciphertext, int cOffset, int[] plaintext, int pOffset);

    public static final class Aes128DecApi extends AesDecApi {

        private final int[] drk = new int[44], data = new int[8];

        Aes128DecApi(int[] rk) {
            System.arraycopy(rk, 40, drk, 0, 4);

            for (int off = 4; off < 40; off += 4) {
                drk[off + 0] = invMixColumns(rk[40 - off + 0]);
                drk[off + 1] = invMixColumns(rk[40 - off + 1]);
                drk[off + 2] = invMixColumns(rk[40 - off + 2]);
                drk[off + 3] = invMixColumns(rk[40 - off + 3]);
            }

            System.arraycopy(rk, 0, drk, 40, 4);
        }

        @Override
        public void decryptBlock(int[] ciphertext, int cOffset, int[] plaintext, int pOffset) {
            invAesRound(ciphertext[cOffset + 0] ^ drk[0], ciphertext[cOffset + 1] ^ drk[1], ciphertext[cOffset + 2] ^ drk[2], ciphertext[cOffset + 3] ^ drk[3], data, 4, drk, 4);
            invAesRound(data, 4, data, 0, drk, 8);
            invAesRound(data, 0, data, 4, drk, 12);
            invAesRound(data, 4, data, 0, drk, 16);
            invAesRound(data, 0, data, 4, drk, 20);
            invAesRound(data, 4, data, 0, drk, 24);
            invAesRound(data, 0, data, 4, drk, 28);
            invAesRound(data, 4, data, 0, drk, 32);
            invAesRound(data, 0, data, 4, drk, 36);
            invAesRoundLast(data, 4, plaintext, pOffset, drk, 40);
        }

    }

    public static final class Aes192DecApi extends AesDecApi {

        private final int[] drk = new int[52], data = new int[8];

        Aes192DecApi(int[] rk) {
            System.arraycopy(rk, 48, drk, 0, 4);

            for (int off = 4; off < 48; off += 4) {
                drk[off + 0] = invMixColumns(rk[48 - off + 0]);
                drk[off + 1] = invMixColumns(rk[48 - off + 1]);
                drk[off + 2] = invMixColumns(rk[48 - off + 2]);
                drk[off + 3] = invMixColumns(rk[48 - off + 3]);
            }

            System.arraycopy(rk, 0, drk, 48, 4);
        }

        @Override
        public void decryptBlock(int[] ciphertext, int cOffset, int[] plaintext, int pOffset) {
            invAesRound(ciphertext[cOffset + 0] ^ drk[0], ciphertext[cOffset + 1] ^ drk[1], ciphertext[cOffset + 2] ^ drk[2], ciphertext[cOffset + 3] ^ drk[3], data, 4, drk, 4);
            invAesRound(data, 4, data, 0, drk, 8);
            invAesRound(data, 0, data, 4, drk, 12);
            invAesRound(data, 4, data, 0, drk, 16);
            invAesRound(data, 0, data, 4, drk, 20);
            invAesRound(data, 4, data, 0, drk, 24);
            invAesRound(data, 0, data, 4, drk, 28);
            invAesRound(data, 4, data, 0, drk, 32);
            invAesRound(data, 0, data, 4, drk, 36);
            invAesRound(data, 4, data, 0, drk, 40);
            invAesRound(data, 0, data, 4, drk, 44);
            invAesRoundLast(data, 4, plaintext, pOffset, drk, 44);
        }

    }

    public static final class Aes256DecApi extends AesDecApi {

        private final int[] drk = new int[60], data = new int[8];

        Aes256DecApi(int[] rk) {
            System.arraycopy(rk, 56, drk, 0, 4);

            for (int off = 4; off < 56; off += 4) {
                drk[off + 0] = invMixColumns(rk[56 - off + 0]);
                drk[off + 1] = invMixColumns(rk[56 - off + 1]);
                drk[off + 2] = invMixColumns(rk[56 - off + 2]);
                drk[off + 3] = invMixColumns(rk[56 - off + 3]);
            }

            System.arraycopy(rk, 0, drk, 56, 4);
        }

        @Override
        public void decryptBlock(int[] ciphertext, int cOffset, int[] plaintext, int pOffset) {
            invAesRound(ciphertext[cOffset + 0] ^ drk[0], ciphertext[cOffset + 1] ^ drk[1], ciphertext[cOffset + 2] ^ drk[2], ciphertext[cOffset + 3] ^ drk[3], data, 4, drk, 4);
            invAesRound(data, 4, data, 0, drk, 8);
            invAesRound(data, 0, data, 4, drk, 12);
            invAesRound(data, 4, data, 0, drk, 16);
            invAesRound(data, 0, data, 4, drk, 20);
            invAesRound(data, 4, data, 0, drk, 24);
            invAesRound(data, 0, data, 4, drk, 28);
            invAesRound(data, 4, data, 0, drk, 32);
            invAesRound(data, 0, data, 4, drk, 36);
            invAesRound(data, 4, data, 0, drk, 40);
            invAesRound(data, 0, data, 4, drk, 44);
            invAesRound(data, 4, data, 0, drk, 48);
            invAesRound(data, 0, data, 4, drk, 52);
            invAesRoundLast(data, 4, plaintext, pOffset, drk, 56);
        }

    }

}
