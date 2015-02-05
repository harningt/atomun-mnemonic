package us.eharning.atomun.mnemonic.spi.electrum.legacy;

import us.eharning.atomun.mnemonic.MnemonicUnit;
import us.eharning.atomun.mnemonic.MnemonicUnitSpi;

/**
 * Internal class to implement the legacy Electrum mnemonic details.
 */
class LegacyElectrumMnemonicUnitSpi extends MnemonicUnitSpi {
    public MnemonicUnit build(CharSequence mnemonicSequence, byte[] entropy) {
        /* Entropy is the seed for this */
        return super.build(mnemonicSequence, entropy, entropy, null);
    }

    /**
     * Get the entropy if possible.
     *
     * @param mnemonicSequence sequence to derive entropy from.
     *
     * @return a derived copy of the entropy byte array.
     */
    @Override
    public byte[] getEntropy(CharSequence mnemonicSequence) {
        return LegacyElectrumMnemonicUtility.toEntropy(mnemonicSequence);
    }

    /**
     * Get a seed from this mnemonic.
     *
     * @param mnemonicSequence sequence to derive the seed from.
     * @param password password to supply for decoding.
     *
     * @return a derived seed.
     */
    @Override
    public byte[] getSeed(CharSequence mnemonicSequence, CharSequence password) {
        if (password != null && password.length() != 0) {
            throw new UnsupportedOperationException("password usage is not supported");
        }
        return getEntropy(mnemonicSequence);
    }
}
