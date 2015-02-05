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
