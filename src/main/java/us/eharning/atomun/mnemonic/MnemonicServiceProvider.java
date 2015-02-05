package us.eharning.atomun.mnemonic;

import us.eharning.atomun.mnemonic.spi.MnemonicBuilderSpi;

/**
 * Common service implementation for mnemonic encoders/decoders.
 *
 * @since 0.1.0
 */
public abstract class MnemonicServiceProvider {
    public abstract MnemonicBuilderSpi getMnemonicBuilder(MnemonicAlgorithm algorithm);
    public abstract MnemonicDecoderSpi getMnemonicDecoder(MnemonicAlgorithm algorithm);
}
