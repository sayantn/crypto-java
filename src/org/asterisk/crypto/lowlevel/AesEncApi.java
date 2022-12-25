/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this licens
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package org.asterisk.crypto.lowlevel;

import static org.asterisk.crypto.helper.Tools.load32BE;
import static org.asterisk.crypto.lowlevel.AesPermutation.aesRound;
import static org.asterisk.crypto.lowlevel.AesPermutation.aesRoundLast;
import static org.asterisk.crypto.lowlevel.AesPermutation.shiftSub;

/**
 *
 * @author Sayantan Chakraborty
 */
public sealed abstract class AesEncApi {

    private static final int[] RCON = {
        0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000,
        0x1B000000, 0x36000000, 0x6c000000, 0xd8000000, 0xab000000, 0x4d000000
    };

    public abstract void encryptBlock(int[] plaintext, int pOffset, int[] ciphertext, int cOffset);

    public abstract AesDecApi decrypter();

    public static final class Aes128EncApi extends AesEncApi {

        private final int[] rk = new int[44], data = new int[8];

        public Aes128EncApi(byte[] key) {
            rk[0] = load32BE(key, 0);
            rk[1] = load32BE(key, 4);
            rk[2] = load32BE(key, 8);
            rk[3] = load32BE(key, 12);

            for (int i = 0, j = 0; j < 10; i += 4, j++) {
                rk[i + 4] = rk[i] ^ shiftSub(rk[i + 3]) ^ RCON[j];
                rk[i + 5] = rk[i + 1] ^ rk[i + 4];
                rk[i + 6] = rk[i + 2] ^ rk[i + 5];
                rk[i + 7] = rk[i + 3] ^ rk[i + 6];
            }
        }

        public Aes128EncApi(int[] key, int offset) {
            System.arraycopy(key, offset, rk, 0, 4);

            for (int i = 0, j = 0; j < 10; i += 4, j++) {
                rk[i + 4] = rk[i] ^ shiftSub(rk[i + 3]) ^ RCON[j];
                rk[i + 5] = rk[i + 1] ^ rk[i + 4];
                rk[i + 6] = rk[i + 2] ^ rk[i + 5];
                rk[i + 7] = rk[i + 3] ^ rk[i + 6];
            }
        }

        @Override
        public void encryptBlock(int[] plaintext, int pOffset, int[] ciphertext, int cOffset) {
            aesRound(plaintext[pOffset + 0] ^ rk[0], plaintext[pOffset + 1] ^ rk[1], plaintext[pOffset + 2] ^ rk[2], plaintext[pOffset + 3] ^ rk[3], data, 4, rk, 4);
            aesRound(data, 4, data, 0, rk, 8);
            aesRound(data, 0, data, 4, rk, 12);
            aesRound(data, 4, data, 0, rk, 16);
            aesRound(data, 0, data, 4, rk, 20);
            aesRound(data, 4, data, 0, rk, 24);
            aesRound(data, 0, data, 4, rk, 28);
            aesRound(data, 4, data, 0, rk, 32);
            aesRound(data, 0, data, 4, rk, 36);
            aesRoundLast(data, 4, ciphertext, cOffset, rk, 40);

        }

        @Override
        public AesDecApi.Aes128DecApi decrypter() {
            return new AesDecApi.Aes128DecApi(rk);
        }

    }

    public static final class Aes192EncApi extends AesEncApi {

        private final int[] rk = new int[52], data = new int[8];

        public Aes192EncApi(byte[] key) {
            rk[0] = load32BE(key, 0);
            rk[1] = load32BE(key, 4);
            rk[2] = load32BE(key, 8);
            rk[3] = load32BE(key, 12);
            rk[4] = load32BE(key, 16);
            rk[5] = load32BE(key, 20);

            for (int i = 0, j = 0; j < 7; j++, i += 7) {
                rk[i + 6] = rk[i] ^ shiftSub(rk[i + 5]) ^ RCON[j];
                rk[i + 7] = rk[i + 1] ^ rk[i + 6];
                rk[i + 8] = rk[i + 2] ^ rk[i + 7];
                rk[i + 9] = rk[i + 3] ^ rk[i + 8];
                rk[i + 10] = rk[i + 4] ^ rk[i + 9];
                rk[i + 11] = rk[i + 5] ^ rk[i + 10];
            }
            rk[48] = rk[42] ^ shiftSub(rk[47]) ^ RCON[7];
            rk[49] = rk[43] ^ rk[48];
            rk[50] = rk[44] ^ rk[49];
            rk[51] = rk[45] ^ rk[50];
        }

        public Aes192EncApi(int[] key, int offset) {
            System.arraycopy(key, offset, rk, 0, 6);

            for (int i = 0, j = 0; j < 7; j++, i += 7) {
                rk[i + 6] = rk[i] ^ shiftSub(rk[i + 5]) ^ RCON[j];
                rk[i + 7] = rk[i + 1] ^ rk[i + 6];
                rk[i + 8] = rk[i + 2] ^ rk[i + 7];
                rk[i + 9] = rk[i + 3] ^ rk[i + 8];
                rk[i + 10] = rk[i + 4] ^ rk[i + 9];
                rk[i + 11] = rk[i + 5] ^ rk[i + 10];
            }
            rk[48] = rk[42] ^ shiftSub(rk[47]) ^ RCON[7];
            rk[49] = rk[43] ^ rk[48];
            rk[50] = rk[44] ^ rk[49];
            rk[51] = rk[45] ^ rk[50];
        }

        @Override
        public void encryptBlock(int[] plaintext, int pOffset, int[] ciphertext, int cOffset) {
            aesRound(plaintext[pOffset + 0] ^ rk[0], plaintext[pOffset + 1] ^ rk[1], plaintext[pOffset + 2] ^ rk[2], plaintext[pOffset + 3] ^ rk[3], data, 4, rk, 4);
            aesRound(data, 4, data, 0, rk, 8);
            aesRound(data, 0, data, 4, rk, 12);
            aesRound(data, 4, data, 0, rk, 16);
            aesRound(data, 0, data, 4, rk, 20);
            aesRound(data, 4, data, 0, rk, 24);
            aesRound(data, 0, data, 4, rk, 28);
            aesRound(data, 4, data, 0, rk, 32);
            aesRound(data, 0, data, 4, rk, 36);
            aesRound(data, 4, data, 0, rk, 40);
            aesRound(data, 0, data, 4, rk, 44);
            aesRoundLast(data, 4, ciphertext, cOffset, rk, 48);
        }

        @Override
        public AesDecApi.Aes192DecApi decrypter() {
            return new AesDecApi.Aes192DecApi(rk);
        }

    }

    public static final class Aes256EncApi extends AesEncApi {

        private final int[] rk = new int[60], data = new int[8];

        public Aes256EncApi(byte[] key) {
            rk[0] = load32BE(key, 0);
            rk[1] = load32BE(key, 4);
            rk[2] = load32BE(key, 8);
            rk[3] = load32BE(key, 12);
            rk[4] = load32BE(key, 16);
            rk[5] = load32BE(key, 20);
            rk[6] = load32BE(key, 24);
            rk[7] = load32BE(key, 28);

            for (int i = 0, j = 0; j < 6; i += 8, j++) {
                rk[i + 8] = rk[i] ^ shiftSub(rk[i + 7]) ^ RCON[j];
                rk[i + 9] = rk[i + 1] ^ rk[i + 8];
                rk[i + 10] = rk[i + 2] ^ rk[i + 9];
                rk[i + 11] = rk[i + 3] ^ rk[i + 10];
                rk[i + 12] = rk[i + 4] ^ shiftSub(Integer.rotateRight(rk[i + 11], 8));
                rk[i + 13] = rk[i + 5] ^ rk[i + 12];
                rk[i + 14] = rk[i + 6] ^ rk[i + 13];
                rk[i + 15] = rk[i + 7] ^ rk[i + 14];
            }
            rk[56] = rk[48] ^ shiftSub(rk[55]) ^ RCON[6];
            rk[57] = rk[49] ^ rk[56];
            rk[58] = rk[50] ^ rk[57];
            rk[59] = rk[51] ^ rk[58];
        }

        public Aes256EncApi(int[] key, int offset) {
            System.arraycopy(key, offset, rk, 0, 8);

            for (int i = 0, j = 0; j < 6; i += 8, j++) {
                rk[i + 8] = rk[i] ^ shiftSub(rk[i + 7]) ^ RCON[j];
                rk[i + 9] = rk[i + 1] ^ rk[i + 8];
                rk[i + 10] = rk[i + 2] ^ rk[i + 9];
                rk[i + 11] = rk[i + 3] ^ rk[i + 10];
                rk[i + 12] = rk[i + 4] ^ shiftSub(Integer.rotateRight(rk[i + 11], 8));
                rk[i + 13] = rk[i + 5] ^ rk[i + 12];
                rk[i + 14] = rk[i + 6] ^ rk[i + 13];
                rk[i + 15] = rk[i + 7] ^ rk[i + 14];
            }
            rk[56] = rk[48] ^ shiftSub(rk[55]) ^ RCON[6];
            rk[57] = rk[49] ^ rk[56];
            rk[58] = rk[50] ^ rk[57];
            rk[59] = rk[51] ^ rk[58];
        }

        @Override
        public void encryptBlock(int[] plaintext, int pOffset, int[] ciphertext, int cOffset) {
            aesRound(plaintext[pOffset + 0] ^ rk[0], plaintext[pOffset + 1] ^ rk[1], plaintext[pOffset + 2] ^ rk[2], plaintext[pOffset + 3] ^ rk[3], data, 4, rk, 4);
            aesRound(data, 4, data, 0, rk, 8);
            aesRound(data, 0, data, 4, rk, 12);
            aesRound(data, 4, data, 0, rk, 16);
            aesRound(data, 0, data, 4, rk, 20);
            aesRound(data, 4, data, 0, rk, 24);
            aesRound(data, 0, data, 4, rk, 28);
            aesRound(data, 4, data, 0, rk, 32);
            aesRound(data, 0, data, 4, rk, 36);
            aesRound(data, 4, data, 0, rk, 40);
            aesRound(data, 0, data, 4, rk, 44);
            aesRound(data, 4, data, 0, rk, 48);
            aesRound(data, 0, data, 4, rk, 52);
            aesRoundLast(data, 4, ciphertext, cOffset, rk, 56);
        }

        @Override
        public AesDecApi.Aes256DecApi decrypter() {
            return new AesDecApi.Aes256DecApi(rk);
        }

    }

}
