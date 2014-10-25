/*
 * Copyright 2014 Thomas Harning Jr. <harningt@gmail.com>
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
 */
abstract class MnemonicUnitSpi {
    private final CharSequence mnemonicSequence;

    /**
     * Construct the implementation wrapping a given mnemonic sequence.
     * @param mnemonicSequence space-delimited sequence of mnemonic words.
     */
    protected MnemonicUnitSpi(CharSequence mnemonicSequence) {
        this.mnemonicSequence = mnemonicSequence;
    }

    /**
     * Get the entropy if possible.
     * @return a copy of the entropy byte array or null if inaccessible.
     */
    public abstract byte[] getEntropy();

    /**
     * Set a custom property specialized for the given algorithm.
     * @param extensionType kind of decoder extension to obtain.
     * By default this rejects as it is not expected to be implemented lower down.
     */
    public <T> T getExtension(Class<T> extensionType) {
        return null;
    }

    /**
     * Get the associated mnemonic string.
     * @return space-delimited sequence of mnemonic words.
     */
    public CharSequence getMnemonicSequence() {
        return mnemonicSequence;
    }

    /**
     * Get a seed from this mnemonic without supplying a password.
     * @return a decoded seed.
     */
    public abstract byte[] getSeed();

    /**
     * Get a seed from this mnemonic.
     * @param password password to supply for decoding.
     * @return a decoded seed.
     */
    public abstract byte[] getSeed(CharSequence password);
}
