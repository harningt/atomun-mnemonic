package us.eharning.atomun.mnemonic.spi;

import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Builder parameter representing entropy fill-in.
 *
 * @since 0.1.0
 */
public abstract class EntropyBuilderParameter implements BuilderParameter {
    public abstract byte[] getEntropy();

    public abstract int getEntropyLength();

    public static EntropyBuilderParameter getRandom(int size) {
        return new RandomEntropyBuilderParameter(size);
    }

    public static EntropyBuilderParameter getStatic(byte[] entropy) {
        return new StaticEntropyBuilderParameter(entropy);
    }

    private static class RandomEntropyBuilderParameter extends EntropyBuilderParameter {
        private static final SecureRandom RNG = new SecureRandom();
        private final int size;

        private RandomEntropyBuilderParameter(int size) {
            this.size = size;
        }

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

        private StaticEntropyBuilderParameter(byte[] entropy) {
            this.entropy = Arrays.copyOf(entropy, entropy.length);
        }

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
