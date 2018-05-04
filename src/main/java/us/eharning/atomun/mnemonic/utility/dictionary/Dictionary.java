/*
 * Copyright 2014, 2015, 2016 Thomas Harning Jr. <harningt@gmail.com>
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

package us.eharning.atomun.mnemonic.utility.dictionary;

import static com.google.common.base.Preconditions.checkNotNull;

import com.google.common.annotations.Beta;
import com.google.common.base.Charsets;
import com.google.common.base.Converter;
import com.google.common.base.Objects;
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.io.ByteSource;
import com.google.common.io.LineProcessor;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

import java.io.IOException;
import java.text.Normalizer;
import java.util.List;
import javax.annotation.Nonnull;
import javax.annotation.concurrent.Immutable;

/**
 * Utility class representing a bidirectional map between integer and string.
 *
 * @since 0.1.0
 */
@Beta
@Immutable
@Nonnull
public class Dictionary extends Converter<Integer, String> {
    private final ImmutableList<String> indexToWordMap;
    private final ImmutableMap<String, Integer> wordToIndexMap;
    private final DictionaryIdentifier identifier;

    /**
     * Construct an instance by loading words from a list.
     *
     * @param wordList
     *         list of words to generate the dictionary from.
     * @param identifier
     *         associated dictionary identifier.
     *
     * @since 0.1.0
     */
    Dictionary(@Nonnull List<String> wordList, @Nonnull DictionaryIdentifier identifier) {
        this.identifier = checkNotNull(identifier);
        indexToWordMap = ImmutableList.copyOf(checkNotNull(wordList));
        ImmutableMap.Builder<String, Integer> builder = ImmutableMap.builder();
        for (int i = 0; i < indexToWordMap.size(); i++) {
            builder.put(indexToWordMap.get(i), i);
        }
        wordToIndexMap = builder.build();
    }

    /**
     * Construct an instance by reading a resource as UTF-8 and line-splitting.
     *
     * @param dictionaryDataSource
     *         reference to source of data for dictionary.
     * @param identifier
     *         associated dictionary identifier.
     *
     * @throws IOException
     *         on an I/O error reading the resource.
     * @since 0.7.0
     */
    Dictionary(@Nonnull ByteSource dictionaryDataSource, @Nonnull DictionaryIdentifier identifier) {
        this(resourceToLines(dictionaryDataSource), identifier);
    }

    /**
     * Utility method to convert a resource URL into a list of lines.
     *
     * @param dataSource
     *         source to generate the line list from.
     *
     * @return list of lines.
     *
     * @throws IOException
     *         on I/O error reading from the resource.
     */
    @SuppressFBWarnings("NP_NONNULL_RETURN_VIOLATION")
    @Nonnull
    private static ImmutableList<String> resourceToLines(@Nonnull ByteSource dataSource) {
        LineProcessor<ImmutableList<String>> lineProcess = new LineProcessor<ImmutableList<String>>() {
            final ImmutableList.Builder<String> result = ImmutableList.builder();

            @Override
            public boolean processLine(@Nonnull String line) throws IOException {
                /* Skip comments and empty lines */
                if (line.startsWith("#") || line.isEmpty()) {
                    return true;
                }
                /* Binding dictionary handling to NFKD normalization */
                line = Normalizer.normalize(line, Normalizer.Form.NFKD);
                result.add(line);
                return true;
            }

            @Override
            public ImmutableList<String> getResult() {
                return result.build();
            }
        };
        try {
            return dataSource.asCharSource(Charsets.UTF_8).readLines(lineProcess);
        } catch (IOException e) {
            throw new IllegalArgumentException("Input source was bad", e);
        }
    }

    @Override
    public boolean equals(Object that) {
        if (this == that) {
            return true;
        }
        if (that == null || getClass() != that.getClass()) {
            return false;
        }
        /* NOTE: Skipping wordToIndexMap due to invariants */
        Dictionary thatDictionary = (Dictionary) that;
        return Objects.equal(indexToWordMap, thatDictionary.indexToWordMap)
                && Objects.equal(identifier, thatDictionary.identifier);
    }

    @Override
    public int hashCode() {
        /* NOTE: Skipping wordToIndexMap due to invariants */
        return Objects.hashCode(indexToWordMap, identifier);
    }

    /**
     * Returns a representation of {@code a} as an instance of type {@code B}. If {@code a} cannot be
     * converted, an unchecked exception (such as {@link IllegalArgumentException}) should be thrown.
     *
     * @param integer
     *         the instance to convert; will never be null
     *
     * @return the converted instance; <b>must not</b> be null
     */
    @SuppressFBWarnings("NP_NONNULL_RETURN_VIOLATION")
    @Nonnull
    @Override
    protected String doForward(@Nonnull Integer integer) {
        Preconditions.checkArgument(integer >= 0 && integer < indexToWordMap.size(), "Unknown dictionary index %s", integer);
        return indexToWordMap.get(integer);
    }

    /**
     * Returns a representation of {@code b} as an instance of type {@code A}. If {@code b} cannot be
     * converted, an unchecked exception (such as {@link IllegalArgumentException}) should be thrown.
     *
     * @param word
     *         the instance to convert; will never be null
     *
     * @return the converted instance; <b>must not</b> be null
     *
     * @throws UnsupportedOperationException
     *         if backward conversion is not implemented; this should be
     *         very rare. Note that if backward conversion is not only unimplemented but
     *         unimplement<i>able</i> (for example, consider a {@code Converter<Chicken, ChickenNugget>}),
     *         then this is not logically a {@code Converter} at all, and should just implement {@link com.google.common.base.Function}.
     */
    @SuppressFBWarnings("NP_NONNULL_RETURN_VIOLATION")
    @Nonnull
    @Override
    protected Integer doBackward(@Nonnull String word) {
        Integer result = wordToIndexMap.get(word);
        Preconditions.checkArgument(null != result, "Unknown dictionary word");
        //noinspection ConstantConditions
        return result;
    }

    /**
     * Obtain the identifier of this dictionary.
     *
     * @return identifier.
     *
     * @since 0.7.0
     */
    public DictionaryIdentifier getIdentifier() {
        return identifier;
    }

    /**
     * Obtains the wordListIdentifier of the dictionary.
     *
     * @return wordListIdentifier.
     *
     * @since 0.1.0
     */
    @Nonnull
    public String getWordListIdentifier() {
        return identifier.getName();
    }

    /**
     * Obtains the size of the dictionary.
     *
     * @return size of the dictionary.
     *
     * @since 0.1.0
     */
    public int getSize() {
        return indexToWordMap.size();
    }
}
