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

import com.google.common.base.Verify;

import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Base class to reduce duplicate code when handling entropy.
 */
abstract class BasicMnemonicBuilderSpi extends MnemonicBuilderSpi {
    private byte[] entropy;
    private int entropyLength;

    /**
     * Encode this instance to a space-delimited series of mnemonic words.
     *
     * @return space-delimited sequence of mnemonic words.
     */
    @Override
    public String build() {
        if (entropy == null && entropyLength == 0) {
            throw new IllegalStateException("entropy or entropyLength must be configured");
        }
        byte[] target;
        if (entropy != null) {
            target = entropy;
        } else {
            target = new byte[entropyLength];
            new SecureRandom().nextBytes(target);
        }

        return build(target);
    }

    /**
     * Set the entropy to generate the mnemonic with.
     *
     * @param entropy data to encode.
     */
    @Override
    public void setEntropy(byte[] entropy) {
        Verify.verifyNotNull(entropy);
        checkEntropyLengthValid(entropy.length);
        if (entropyLength > 0) {
            throw new IllegalStateException("entropy cannot be set of entropyLength is set");
        }
        this.entropy = Arrays.copyOf(entropy, entropy.length);
    }

    /**
     * Set the length of the desired entropy to generate the mnemonic with.
     *
     * @param entropyLength number of bytes of entropy to use.
     */
    @Override
    public void setEntropyLength(int entropyLength) {
        checkEntropyLengthValid(entropyLength);
        if (null != entropy) {
            throw new IllegalStateException("entropyLength cannot be set of entropy is set");
        }
        this.entropyLength = entropyLength;
    }

    /**
     * Encode the given entropy to a space-delimited series of mnemonic words.
     *
     * @return space-delimited sequence of mnemonic words.
     */
    protected abstract String build(byte[] entropy);

    /**
     * Return if the given entropy length is valid.
     *
     * @param entropyLength number of bytes of entropy.
     *
     * @throws java.lang.IllegalArgumentException if the entropyLength is invalid
     */
    protected abstract void checkEntropyLengthValid(int entropyLength);
}
