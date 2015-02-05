package us.eharning.atomun.mnemonic.spi.electrum.legacy;

import us.eharning.atomun.mnemonic.*;
import us.eharning.atomun.mnemonic.spi.MnemonicBuilderSpi;

/**
 * Registration class to perform the necessary default service provider registrations.
 */
public class LegacyElectrumMnemonicService extends MnemonicServiceProvider {
    private static final MnemonicBuilderSpi BUILDER_SPI = new LegacyElectrumMnemonicBuilderSpi();
    private static final MnemonicDecoderSpi DECODER_SPI = new LegacyElectrumMnemonicDecoderSpi();

    @Override
    public MnemonicBuilderSpi getMnemonicBuilder(MnemonicAlgorithm algorithm) {
        if (algorithm != MnemonicAlgorithm.LegacyElectrum) {
            return null;
        }
        return BUILDER_SPI;
    }

    @Override
    public MnemonicDecoderSpi getMnemonicDecoder(MnemonicAlgorithm algorithm) {
        if (algorithm != MnemonicAlgorithm.LegacyElectrum) {
            return null;
        }
        return DECODER_SPI;
    }

}
