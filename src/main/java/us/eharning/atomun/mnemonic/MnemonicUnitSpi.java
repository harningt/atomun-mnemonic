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
import com.google.common.collect.ClassToInstanceMap;

/**
 * Service provider to back the MnemonicDecoder.
 * Primarily to present a consistent API.
 *
 * @since 0.1.0
 */
public abstract class MnemonicUnitSpi {
    /**
     * Utility method to return a wrapped instance of this SPI.
     *
     * @return wrapped instance.
     *
     * @since 0.1.0
     */
    protected MnemonicUnit build(CharSequence mnemonicSequence, byte[] entropy, byte[] seed, ClassToInstanceMap<Object> extentions) {
        Verify.verifyNotNull(mnemonicSequence);
        return new MnemonicUnit(this, mnemonicSequence, entropy, seed, extentions);
    }

    /**
     * Get the entropy if possible.
     *
     * @param mnemonicSequence sequence to derive the entropy for.
     *
     * @return a copy of the entropy byte array or null if inaccessible.
     *
     * @since 0.1.0
     */
    public abstract byte[] getEntropy(CharSequence mnemonicSequence);

    /**
     * Get a custom decoder extension to obtain custom values.
     *
     * By default this rejects as it is not expected to be implemented lower down.
     *
     * @param mnemonicSequence sequence to determine the extensions for.
     * @param extensionType kind of decoder extension to obtain.
     *
     * @return typed extension if available, else null.
     *
     * @since 0.1.0
     */
    public <T> T getExtension(CharSequence mnemonicSequence, Class<T> extensionType) {
        return null;
    }

    /**
     * Get a seed from this mnemonic.
     *
     *
     * @param mnemonicSequence sequence to derive the seed from.
     * @param password password to supply for decoding.
     *
     * @return a derived seed.
     *
     * @since 0.1.0
     */
    public abstract byte[] getSeed(CharSequence mnemonicSequence, CharSequence password);
}
