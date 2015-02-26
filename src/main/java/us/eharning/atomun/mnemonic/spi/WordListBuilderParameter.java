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

import javax.annotation.Nonnull;
import javax.annotation.concurrent.Immutable;

/**
 * Builder parameter representing word list identifier fill-in.
 *
 * @since 0.1.0
 */
@Beta
@Immutable
public class WordListBuilderParameter implements BuilderParameter {
    private final String wordListIdentifier;

    /**
     * Construct an instance given the provided word list identifier.
     *
     * @param wordListIdentifier identifier to configure the builder with.
     */
    private WordListBuilderParameter(@Nonnull String wordListIdentifier) {
        this.wordListIdentifier = wordListIdentifier;
    }

    /**
     * Obtain the wordListIdentifier to configure the builder with.
     *
     * @return configured word list identifier.
     */
    @Nonnull
    public String getWordListIdentifier() {
        return wordListIdentifier;
    }

    /**
     * Obtain a parameter instance given the provided word list identifier.
     *
     * @param wordListIdentifier identifier to configure the builder with.
     *
     * @return wrapped wordListIdentifier parameter.
     */
    @Nonnull
    public static WordListBuilderParameter getWordList(@Nonnull String wordListIdentifier) {
        return new WordListBuilderParameter(wordListIdentifier);
    }
}
