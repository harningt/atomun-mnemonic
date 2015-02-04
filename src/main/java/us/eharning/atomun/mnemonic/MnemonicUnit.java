/*
 * Copyright 2014, 2015 Thomas Harning Jr. <harningt@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package us.eharning.atomun.mnemonic;

/**
 * Service provider to back the MnemonicDecoder.
 * Primarily to present a consistent API.
 *
 * @since 0.0.1
 */
public final class MnemonicUnit {
    private final MnemonicUnitSpi spi;

    /**
     * Construct a new MnemonicUnit wrapping the given implementation.
     *
     * @param spi implementation.
     */
    MnemonicUnit(MnemonicUnitSpi spi) {
        this.spi = spi;
    }

    /**
     * Get the entropy if possible.
     *
     * @return a copy of the entropy byte array or null if inaccessible.
     *
     * @since 0.0.1
     */
    public byte[] getEntropy() {
        return spi.getEntropy();
    }

    /**
     * Get a custom decoder extension to obtain custom values.
     *
     * By default this rejects as it is not expected to be implemented lower down.
     *
     * @param extensionType kind of decoder extension to obtain.
     *
     * @return typed extension if available, else null.
     *
     * @since 0.0.1
     */
    public <T> T getExtension(Class<T> extensionType) {
        return spi.getExtension(extensionType);
    }

    /**
     * Get the associated mnemonic string.
     *
     * @return space-delimited sequence of mnemonic words.
     *
     * @since 0.0.1
     */
    public CharSequence getMnemonic() {
        return spi.getMnemonicSequence();
    }

    /**
     * Get a seed from this mnemonic without supplying a password.
     *
     * @return a derived seed.
     *
     * @since 0.0.1
     */
    public byte[] getSeed() {
        return spi.getSeed();
    }

    /**
     * Get a seed from this mnemonic.
     *
     * @param password password to supply for decoding.
     *
     * @return a derived seed.
     *
     * @since 0.0.1
     */
    public byte[] getSeed(CharSequence password) {
        return spi.getSeed(password);
    }
}
