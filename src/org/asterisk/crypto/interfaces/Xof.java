/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this licens
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Interface.java to edit this template
 */
package org.asterisk.crypto.interfaces;

/**
 *
 * @author Sayantan Chakraborty
 */
public interface Xof extends Digest {

    @Override
    Engine start();

    static interface Engine extends Digest.Engine {

        void startDigesting();

        void continueDigesting(byte[] dest, int offset, int length);

        @Override
        default void digestTo(byte[] dest, int offset) {
            startDigesting();
            continueDigesting(dest, offset, getAlgorithm().digestSize());
        }

        default byte[] digest(int length) {
            var digest = new byte[length];
            startDigesting();
            continueDigesting(digest, 0, length);
            return digest;
        }

        @Override
        Xof getAlgorithm();

    }

}
