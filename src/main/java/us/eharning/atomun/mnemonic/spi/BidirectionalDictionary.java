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
import com.google.common.base.Charsets;
import com.google.common.base.Converter;
import com.google.common.base.Objects;
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.io.LineProcessor;
import com.google.common.io.Resources;

import java.io.IOException;
import java.net.URL;
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
public class BidirectionalDictionary extends Converter<Integer, String> {
    private final ImmutableList<String> indexToWordMap;
    private final ImmutableMap<String, Integer> wordToIndexMap;
    private final String wordListIdentifier;

    /**
     * Construct an instance by loading words from a list.
     *
     * @param wordList
     *         list of words to generate the dictionary from.
     * @param wordListIdentifier
     *         associated word list identifier.
     *
     * @since 0.1.0
     */
    public BidirectionalDictionary(@Nonnull List<String> wordList, @Nonnull String wordListIdentifier) {
        this.wordListIdentifier = wordListIdentifier;
        indexToWordMap = ImmutableList.copyOf(wordList);
        ImmutableMap.Builder<String, Integer> builder = ImmutableMap.builder();
        for (int i = 0; i < indexToWordMap.size(); i++) {
            builder.put(indexToWordMap.get(i), i);
        }
        wordToIndexMap = builder.build();
    }

    /**
     * Construct an instance by reading a resource as UTF-8 and line-splitting.
     *
     * @param dictionaryLocation
     *         resource location to generate the dictionary from.
     * @param wordListIdentifier
     *         associated word list identifier.
     *
     * @throws IOException
     *         on an I/O error reading the resource.
     * @since 0.1.0
     */
    public BidirectionalDictionary(@Nonnull URL dictionaryLocation, @Nonnull String wordListIdentifier) throws IOException {
        this(resourceToLines(dictionaryLocation), wordListIdentifier);
    }

    /**
     * Utility method to convert a resource URL into a list of lines.
     *
     * @param resource
     *         location to generate the line list from.
     *
     * @return list of lines.
     *
     * @throws IOException
     *         on I/O error reading from the resource.
     */
    @Nonnull
    private static ImmutableList<String> resourceToLines(@Nonnull URL resource) throws IOException {
        LineProcessor<ImmutableList<String>> lineProcess = new LineProcessor<ImmutableList<String>>() {
            final ImmutableList.Builder<String> result = ImmutableList.builder();

            @Override
            public boolean processLine(@Nonnull String line) throws IOException {
                result.add(line);
                return true;
            }

            @Override
            public ImmutableList<String> getResult() {
                return result.build();
            }
        };
        return Resources.readLines(resource, Charsets.UTF_8, lineProcess);
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
        BidirectionalDictionary thatDictionary = (BidirectionalDictionary) that;
        return Objects.equal(indexToWordMap, thatDictionary.indexToWordMap)
                && Objects.equal(wordListIdentifier, thatDictionary.wordListIdentifier);
    }

    @Override
    public int hashCode() {
        /* NOTE: Skipping wordToIndexMap due to invariants */
        return Objects.hashCode(indexToWordMap, wordListIdentifier);
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
    @Nonnull
    @Override
    protected String doForward(@Nonnull Integer integer) {
        String result = indexToWordMap.get(integer);
        Preconditions.checkArgument(null != result, "Unknown dictionary index");
        //noinspection ConstantConditions
        return result;
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
    @Nonnull
    @Override
    protected Integer doBackward(@Nonnull String word) {
        Integer result = wordToIndexMap.get(word);
        Preconditions.checkArgument(null != result, "Unknown dictionary word");
        //noinspection ConstantConditions
        return result;
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
        return wordListIdentifier;
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
