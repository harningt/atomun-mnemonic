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
package us.eharning.atomun.mnemonic;

import com.google.common.base.Charsets;
import com.google.common.base.Converter;
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.io.LineProcessor;
import com.google.common.io.Resources;

import java.io.IOException;
import java.net.URL;

/**
 * Utility class representing a bidirectional map between integer and string.
 */
class BidirectionalDictionary extends Converter<Integer, String> {
    private final ImmutableList<String> INTEGER_TO_DICTIONARY;
    private final ImmutableMap<String, Integer> DICTIONARY_TO_INTEGER;

    private static ImmutableList<String> resourceToLines(URL resource) throws IOException {
        LineProcessor<ImmutableList<String>> lineProcess = new LineProcessor<ImmutableList<String>>() {
            final ImmutableList.Builder<String> result = ImmutableList.builder();
            @Override
            public boolean processLine(String line) throws IOException {
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

    public BidirectionalDictionary(URL dictionaryLocation) throws IOException {
        INTEGER_TO_DICTIONARY = resourceToLines(dictionaryLocation);
        ImmutableMap.Builder<String, Integer> builder = ImmutableMap.builder();
        for (int i = 0; i < INTEGER_TO_DICTIONARY.size(); i++) {
            builder.put(INTEGER_TO_DICTIONARY.get(i), i);
        }
        DICTIONARY_TO_INTEGER = builder.build();
    }

    /**
     * Returns a representation of {@code a} as an instance of type {@code B}. If {@code a} cannot be
     * converted, an unchecked exception (such as {@link IllegalArgumentException}) should be thrown.
     *
     * @param integer the instance to convert; will never be null
     * @return the converted instance; <b>must not</b> be null
     */
    @Override
    protected String doForward(Integer integer) {
        String result = INTEGER_TO_DICTIONARY.get(integer);
        Preconditions.checkArgument(null != result, "Unknown dictionary index");
        return result;
    }

    /**
     * Returns a representation of {@code b} as an instance of type {@code A}. If {@code b} cannot be
     * converted, an unchecked exception (such as {@link IllegalArgumentException}) should be thrown.
     *
     * @param s the instance to convert; will never be null
     * @return the converted instance; <b>must not</b> be null
     * @throws UnsupportedOperationException if backward conversion is not implemented; this should be
     *                                       very rare. Note that if backward conversion is not only unimplemented but
     *                                       unimplement<i>able</i> (for example, consider a {@code Converter<Chicken, ChickenNugget>}),
     *                                       then this is not logically a {@code Converter} at all, and should just implement {@link
     *                                       com.google.common.base.Function}.
     */
    @Override
    protected Integer doBackward(String s) {
        Integer result = DICTIONARY_TO_INTEGER.get(s);
        Preconditions.checkArgument(null != result, "Unknown dictionary word");
        return result;
    }
}
