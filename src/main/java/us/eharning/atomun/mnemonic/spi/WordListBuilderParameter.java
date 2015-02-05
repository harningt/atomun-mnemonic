package us.eharning.atomun.mnemonic.spi;

/**
 * Builder parameter representing word list identifier fill-in.
 *
 * @since 0.1.0
 */
public class WordListBuilderParameter implements BuilderParameter {
    private final String wordListIdentifier;

    private WordListBuilderParameter(String wordListIdentifier) {
        this.wordListIdentifier = wordListIdentifier;
    }

    public String getWordListIdentifier() {
        return wordListIdentifier;
    }

    public static WordListBuilderParameter getWordList(String wordListIdentifier) {
        return new WordListBuilderParameter(wordListIdentifier);
    }
}
