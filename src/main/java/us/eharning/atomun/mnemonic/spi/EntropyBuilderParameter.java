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

import com.google.common.annotations.Beta;

import java.security.SecureRandom;
import java.util.Arrays;
import javax.annotation.Nonnull;
import javax.annotation.concurrent.Immutable;

/**
 * Builder parameter representing entropy fill-in.
 *
 * @since 0.1.0
 */
@Beta
@Immutable
public abstract class EntropyBuilderParameter implements BuilderParameter {
    /**
     * Obtain an entropy builder that will generate random entropy bytes of the given size.
     *
     * @param size
     *         number of bytes of entropy to generate for each call to #getEntropy().
     *
     * @return entropy builder instance.
     */
    @Nonnull
    public static EntropyBuilderParameter getRandom(int size) {
        return new RandomEntropyBuilderParameter(size);
    }

    /**
     * Obtain an entropy builder that will return a consistent entropy sequence.
     *
     * @param entropy
     *         bytes to return in #getEntropy()..
     *
     * @return entropy builder instance.
     */
    @Nonnull
    public static EntropyBuilderParameter getStatic(@Nonnull byte[] entropy) {
        return new StaticEntropyBuilderParameter(entropy);
    }

    /**
     * Get a sequence of bytes representing the entropy to use for building.
     * Must be called once per build because this value may change per-call.
     *
     * @return configured entropy data for building mnemonic sequences.
     */
    @Nonnull
    public abstract byte[] getEntropy();

    /**
     * Obtain the number of bytes of entropy configured.
     *
     * @return number of bytes that #getEntropy() will return
     */
    public abstract int getEntropyLength();

    /**
     * Internal entropy builder that will return random entropy of a given size.
     */
    private static class RandomEntropyBuilderParameter extends EntropyBuilderParameter {
        private static final SecureRandom RNG = new SecureRandom();
        private final int size;

        /**
         * Construct the internal entropy builder that will return random entropy of the given size.
         *
         * @param size
         *         number of bytes to return in #getEntropy().
         */
        private RandomEntropyBuilderParameter(int size) {
            this.size = size;
        }

        /**
         * Get a sequence of bytes representing the entropy to use for building.
         * <p/>
         * Must be called once per build because this value may change per-call.
         * NOTE: In this instance, the value is securely generated each time.
         *
         * @return configured entropy data for building mnemonic sequences.
         */
        @Nonnull
        public byte[] getEntropy() {
            byte[] entropy = new byte[size];
            RNG.nextBytes(entropy);
            return entropy;
        }

        /**
         * Obtain the number of bytes of entropy configured.
         *
         * @return number of bytes that #getEntropy() will return
         */
        @Override
        public int getEntropyLength() {
            return size;
        }
    }

    /**
     * Internal entropy builder that will return a copy of provided entropy.
     */
    private static class StaticEntropyBuilderParameter extends EntropyBuilderParameter {
        private final byte[] entropy;

        /**
         * Construct the internal entropy builder that will return a copy of the given entropy.
         *
         * @param entropy
         *         bytes to return in #getEntropy().
         */
        private StaticEntropyBuilderParameter(@Nonnull byte[] entropy) {
            this.entropy = Arrays.copyOf(entropy, entropy.length);
        }

        /**
         * Get a sequence of bytes representing the entropy to use for building.
         * <p/>
         * NOTE: In this instance, the value does not change per-call.
         *
         * @return configured entropy data for building mnemonic sequences.
         */
        @Nonnull
        @Override
        public byte[] getEntropy() {
            return Arrays.copyOf(entropy, entropy.length);
        }

        /**
         * Obtain the number of bytes of entropy configured.
         *
         * @return number of bytes that #getEntropy() will return
         */
        @Override
        public int getEntropyLength() {
            return entropy.length;
        }
    }

}
