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
package us.eharning.atomun.mnemonic.spi;

/**
 * Mnemonic build SPI concentrating on being a static instance that
 * offers up sanity-checks and enhanced APIs as necessary.
 *
 * @since 0.1.0
 */
public abstract class MnemonicBuilderSpi {
    /**
     * Generate the mnemonic sequence given the input parameters.
     *
     * @param parameters builder parameters to drive the process.
     *
     * @return the generated mnemonic sequence.
     *
     * @since 0.1.0
     */
    public abstract String generateMnemonic(BuilderParameter... parameters);

    /**
     * Validate the builder parameters.
     *
     * @param parameters builder parameters to validate.
     *
     * @throws RuntimeException varieties in case of invalid input.
     *
     * @since 0.1.0
     */
    public abstract void validate(BuilderParameter... parameters);
}
