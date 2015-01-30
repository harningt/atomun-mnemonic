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
 * Service provider to back the MnemonicBuilder.
 * Primarily to present a consistent API.
 */
abstract class MnemonicBuilderSpi {
    /**
     * Encode this instance to a space-delimited series of mnemonic words.
     *
     * @return space-delimited sequence of mnemonic words.
     */
    public abstract String build();

    /**
     * Set a custom property specialized for the given algorithm.
     *
     * By default this rejects as it is not expected to be implemented lower down.
     *
     * @param extensionType kind of builder extension to obtain.
     */
    public <T> T getExtension(Class<T> extensionType) {
        return null;
    }

    /**
     * Set the entropy to generate the mnemonic with.
     *
     * @param entropy data to encode.
     */
    public abstract void setEntropy(byte[] entropy);

    /**
     * Set the length of the desired entropy to generate the mnemonic with.
     *
     * @param entropyLength number of bytes of entropy to use.
     */
    public abstract void setEntropyLength(int entropyLength);

    /**
     * Set the word list to use for encoding the mnemonic.
     *
     * By default this rejects as it is not expected to be implemented lower down.
     *
     * @param wordListIdentifier name of the word list to use.
     */
    public void setWordList(String wordListIdentifier) {
        throw new UnsupportedOperationException("setWordList is not supported");
    }
}
