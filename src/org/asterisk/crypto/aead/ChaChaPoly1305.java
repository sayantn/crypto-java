/*
 * Copyright (C) 2022 Sayantan Chakraborty
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */
package org.asterisk.crypto.aead;

import java.lang.foreign.MemorySegment;
import org.asterisk.crypto.Tested;
import org.asterisk.crypto.helper.Tools;
import org.asterisk.crypto.interfaces.AuthenticatedCipher;
import org.asterisk.crypto.mac.Poly1305;
import org.asterisk.crypto.stream.ChaCha;

/**
 *
 * @author Sayantan Chakraborty
 */
public enum ChaChaPoly1305 implements AuthenticatedCipher {

    CHACHA20_POLY1305(ChaCha.CHACHA20),
    @Tested
    CHACHA20_POLY1305_IETF(ChaCha.CHACHA20_IETF),
    CHACHA12_POLY1305(ChaCha.CHACHA12),
    CHACHA6_POLY1305(ChaCha.CHACHA6);

    private final ChaCha cipher;

    private ChaChaPoly1305(ChaCha cipher) {
        this.cipher = cipher;
    }

    @Override
    public EncryptEngine startEncryption(byte[] key, byte[] iv) {
        return new EncryptEngine() {

            private final ChaCha.ChaChaEngine encrypter = cipher.startEncryption(key, iv);
            private final Poly1305.Poly1305Engine mac = encrypter.keyPoly1305();

            private boolean ingestingAAD = true;

            private long aadlen = 0, msglen = 0;

            @Override
            public void ingestAAD(MemorySegment aad) {
                if (!ingestingAAD) {
                    throw new IllegalStateException("Cannot ingest AAD after starting to encrypt");
                }
                aadlen += aad.byteSize();
                mac.ingest(aad);
            }

            @Override
            public long encrypt(MemorySegment plaintext, MemorySegment ciphertext) {
                if (ingestingAAD) {
                    if ((aadlen & 15) != 0) {
                        mac.ingest(new byte[16 - (int) (aadlen & 15)]);
                    }
                    ingestingAAD = false;
                }
                msglen += plaintext.byteSize();
                long offset = encrypter.encrypt(plaintext, ciphertext);
                mac.ingest(ciphertext.asSlice(0, offset));
                return offset;
            }

            @Override
            public int finish(MemorySegment ciphertext) {
                int offset;

                byte[] buffer = new byte[16];
                if (ingestingAAD) {
                    offset = 0;
                    if ((aadlen & 15) != 0) {
                        mac.ingest(buffer, 0, 16 - (int) (aadlen & 15));
                    }
                    ingestingAAD = false;
                } else {
                    offset = encrypter.finish(ciphertext);
                    mac.ingest(ciphertext.asSlice(0, offset));
                    if ((msglen & 15) != 0) {
                        mac.ingest(buffer, 0, 16 - (int) (msglen & 15));
                    }
                }
                Tools.store64LE(aadlen, buffer, 0);
                Tools.store64LE(msglen, buffer, 8);
                mac.ingest(buffer);

                return offset;
            }

            @Override
            public void authenticate(byte[] tag, int offset, int length) {
                mac.authenticateTo(tag, offset, length);
            }

            @Override
            public AuthenticatedCipher getAlgorithm() {
                return ChaChaPoly1305.this;
            }
        };
    }

    @Override
    public DecryptEngine startDecryption(byte[] key, byte[] iv) {
        return new DecryptEngine() {

            private final ChaCha.ChaChaEngine encrypter = cipher.startEncryption(key, iv);
            private final Poly1305.Poly1305Engine mac = encrypter.keyPoly1305();

            private boolean ingestingAAD = true;

            private long aadlen = 0, msglen = 0;

            @Override
            public void ingestAAD(MemorySegment aad) {
                if (!ingestingAAD) {
                    throw new IllegalStateException("Cannot ingest AAD after starting to encrypt");
                }
                aadlen += aad.byteSize();
                mac.ingest(aad);
            }

            @Override
            public long decrypt(MemorySegment ciphertext, MemorySegment plaintext) {
                if (ingestingAAD) {
                    if ((aadlen & 15) != 0) {
                        mac.ingest(new byte[16 - (int) (aadlen & 15)]);
                    }
                    ingestingAAD = false;
                }
                mac.ingest(ciphertext);
                long offset = encrypter.encrypt(ciphertext, plaintext);
                msglen += offset;
                return offset;
            }

            @Override
            public int finish(MemorySegment plaintext) {
                int offset;

                byte[] buffer = new byte[16];
                if (ingestingAAD) {
                    offset = 0;
                    if ((aadlen & 15) != 0) {
                        mac.ingest(buffer, 0, 16 - (int) (aadlen & 15));
                    }
                    ingestingAAD = false;
                } else {
                    offset = encrypter.finish(plaintext);
                    msglen += offset;
                    if ((msglen & 15) != 0) {
                        mac.ingest(buffer, 0, 16 - (int) (msglen & 15));
                    }
                }

                Tools.store64LE(aadlen, buffer, 0);
                Tools.store64LE(msglen, buffer, 8);
                mac.ingest(buffer);

                return offset;
            }

            @Override
            public boolean verify(byte[] tag, int offset, int length) {
                return mac.verify(tag, offset, length);
            }

            @Override
            public AuthenticatedCipher getAlgorithm() {
                return ChaChaPoly1305.this;
            }
        };
    }

    @Override
    public int keyLength() {
        return 32;
    }

    @Override
    public int ivLength() {
        return cipher.ivLength();
    }

    @Override
    public int tagLength() {
        return 16;
    }



}
