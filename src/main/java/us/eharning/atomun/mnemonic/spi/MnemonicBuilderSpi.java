/*
 * Copyright 2014, 2015, 2016 Thomas Harning Jr. <harningt@gmail.com>
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

package us.eharning.atomun.mnemonic.spi;

import static com.google.common.base.Preconditions.checkNotNull;

import com.google.common.annotations.Beta;
import us.eharning.atomun.mnemonic.MnemonicAlgorithm;
import us.eharning.atomun.mnemonic.MnemonicUnit;

import javax.annotation.Nonnull;
import javax.annotation.concurrent.Immutable;

/**
 * Mnemonic build SPI concentrating on being a static instance that
 * offers up sanity-checks and enhanced APIs as necessary.
 *
 * @since 0.1.0
 */
@Beta
@Immutable
public abstract class MnemonicBuilderSpi {
    @Nonnull
    private final MnemonicAlgorithm algorithm;

    /**
     * Construct a new SPI with the given algorithm.
     *
     * @param algorithm
     *         implemented mnemonic algorithm.
     */
    protected MnemonicBuilderSpi(@Nonnull MnemonicAlgorithm algorithm) {
        this.algorithm = checkNotNull(algorithm);
    }

    /**
     * Get the implemented mnemonic algorithm.
     *
     * @return implemented mnemonic algorithm.
     */
    @Nonnull
    public MnemonicAlgorithm getAlgorithm() {
        return algorithm;
    }

    /**
     * Generate the mnemonic sequence given the input parameters.
     *
     * @param parameters
     *         builder parameters to drive the process.
     *
     * @return the generated mnemonic sequence.
     *
     * @since 0.1.0
     */
    @Nonnull
    public abstract String generateMnemonic(BuilderParameter... parameters);

    /**
     * Encode this instance to a wrapped mnemonic unit.
     * The default implementation performs a naive generation without optimisation.
     *
     * @param builder
     *         instance to construct MnemonicUnit with.
     * @param parameters
     *         builder parameters to drive the process.
     *
     * @return MnemonicUnit instance wrapping build results.
     *
     * @since 0.2.0
     */
    @Nonnull
    public MnemonicUnit generateMnemonicUnit(@Nonnull MnemonicUnit.Builder builder, BuilderParameter... parameters) {
        String mnemonicSequence = generateMnemonic(parameters);
        /* Check for word list since that can be input. */
        String wordListIdentifier = null;
        for (BuilderParameter parameter : parameters) {
            if (parameter instanceof WordListBuilderParameter) {
                wordListIdentifier = ((WordListBuilderParameter) parameter).getWordListIdentifier();
            }
        }
        return MnemonicUnit.decodeMnemonic(getAlgorithm(), mnemonicSequence, wordListIdentifier);
    }

    /**
     * Validate the builder parameters.
     *
     * @param parameters
     *         builder parameters to validate.
     *
     * @throws RuntimeException
     *         varieties in case of invalid input.
     * @since 0.1.0
     */
    public abstract void validate(BuilderParameter... parameters);
}
