package us.eharning.atomun.mnemonic.spi.bip0039;

import us.eharning.atomun.mnemonic.MnemonicAlgorithm;
import us.eharning.atomun.mnemonic.MnemonicDecoderSpi;
import us.eharning.atomun.mnemonic.MnemonicServiceProvider;
import us.eharning.atomun.mnemonic.spi.MnemonicBuilderSpi;

/**
 * Registration class to perform the necessary default service provider registrations.
 */
public class BIP0039MnemonicService extends MnemonicServiceProvider {
    private static final MnemonicBuilderSpi BUILDER_SPI = new BIP0039MnemonicBuilderSpi();
    private static final MnemonicDecoderSpi DECODER_SPI = new BIP0039MnemonicDecoderSpi();

    @Override
    public MnemonicBuilderSpi getMnemonicBuilder(MnemonicAlgorithm algorithm) {
        if (algorithm != MnemonicAlgorithm.BIP0039) {
            return null;
        }
        return BUILDER_SPI;
    }

    @Override
    public MnemonicDecoderSpi getMnemonicDecoder(MnemonicAlgorithm algorithm) {
        if (algorithm != MnemonicAlgorithm.BIP0039) {
            return null;
        }
        return DECODER_SPI;
    }

}
