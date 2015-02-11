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

import javax.annotation.Nonnull;
import javax.annotation.concurrent.Immutable;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Builder parameter representing entropy fill-in.
 *
 * @since 0.1.0
 */
@Immutable
public abstract class EntropyBuilderParameter implements BuilderParameter {
    @Nonnull
    public abstract byte[] getEntropy();

    public abstract int getEntropyLength();

    @Nonnull
    public static EntropyBuilderParameter getRandom(int size) {
        return new RandomEntropyBuilderParameter(size);
    }

    @Nonnull
    public static EntropyBuilderParameter getStatic(@Nonnull byte[] entropy) {
        return new StaticEntropyBuilderParameter(entropy);
    }

    private static class RandomEntropyBuilderParameter extends EntropyBuilderParameter {
        private static final SecureRandom RNG = new SecureRandom();
        private final int size;

        private RandomEntropyBuilderParameter(int size) {
            this.size = size;
        }

        @Nonnull
        public byte[] getEntropy() {
            byte[] entropy = new byte[size];
            RNG.nextBytes(entropy);
            return entropy;
        }

        @Override
        public int getEntropyLength() {
            return size;
        }
    }

    private static class StaticEntropyBuilderParameter extends EntropyBuilderParameter {
        private final byte[] entropy;

        private StaticEntropyBuilderParameter(@Nonnull byte[] entropy) {
            this.entropy = Arrays.copyOf(entropy, entropy.length);
        }

        @Nonnull
        @Override
        public byte[] getEntropy() {
            return entropy;
        }

        @Override
        public int getEntropyLength() {
            return entropy.length;
        }
    }

}
