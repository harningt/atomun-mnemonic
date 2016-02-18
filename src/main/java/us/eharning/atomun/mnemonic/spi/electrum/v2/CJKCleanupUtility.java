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

package us.eharning.atomun.mnemonic.spi.electrum.v2;

import com.google.common.base.CharMatcher;
import com.google.common.base.Charsets;
import com.google.common.base.Splitter;
import com.google.common.collect.ImmutableRangeSet;
import com.google.common.collect.Range;
import com.google.common.collect.RangeSet;
import com.google.common.collect.TreeRangeSet;
import com.google.common.io.LineProcessor;
import com.google.common.io.Resources;

import java.io.IOException;
import java.util.Iterator;
import javax.annotation.Nonnull;

/**
 * Utility class to help handle cleanup implemented in Electrum for CJK.
 */
class CJKCleanupUtility {
    private static final RangeSet<Integer> CJK_RANGES = buildRanges();

    private static RangeSet<Integer> buildRanges() {
        LineProcessor<RangeSet<Integer>> lineProcess = new LineProcessor<RangeSet<Integer>>() {
            private final RangeSet<Integer> resultBuilder = TreeRangeSet.create();

            @Override
            public boolean processLine(@Nonnull String line) throws IOException {
                /* Skip comments and empty lines */
                int commentIndex = line.indexOf('#');
                if (commentIndex >= 0) {
                    line = line.substring(0, commentIndex);
                }
                line = CharMatcher.whitespace().trimFrom(line);
                if (line.isEmpty()) {
                    return true;
                }
                /* NOTE: Assuming 0xHEX-0xHEX notation */
                int splitMarker = line.indexOf('-');
                assert splitMarker >= 0;
                int start = Integer.parseInt(line.substring(2, splitMarker), 16);
                int stop = Integer.parseInt(line.substring(splitMarker + 3), 16);
                resultBuilder.add(Range.closed(start, stop));
                return true;
            }

            @Override
            public RangeSet<Integer> getResult() {
                return ImmutableRangeSet.copyOf(resultBuilder);
            }
        };
        try {
            return Resources.readLines(MnemonicUtility.class.getResource("cjk_ranges.dat"), Charsets.UTF_8, lineProcess);
        } catch (IOException e) {
            throw new Error(e);
        }
    }

    public String cleanup(String input) {
        /* Check for non-ascii range to short-circuit fast */
        if (CharMatcher.ascii().matchesAllOf(input)) {
            /* All ascii, skip */
            return input;
        }
        /* Split into words and join specially */
        StringBuilder cleanBuilder = new StringBuilder(input.length());
        Iterator<String> splitIterator = Splitter.on(' ').split(input).iterator();
        /* All one unit - no space removal necessary */
        if (!splitIterator.hasNext()) {
            return input;
        }
        String previousWord = splitIterator.next();
        cleanBuilder.append(previousWord);
        while (splitIterator.hasNext()) {
            String nextWord = splitIterator.next();
            if (hasSpaceBetween(previousWord, nextWord)) {
                cleanBuilder.append(' ');
            }
            cleanBuilder.append(nextWord);
            previousWord = nextWord;
        }
        return cleanBuilder.toString();
    }

    private boolean hasSpaceBetween(String previousWord, String nextWord) {
        int previousCodepoint = previousWord.codePointBefore(previousWord.length());
        if (!CJK_RANGES.contains(previousCodepoint)) {
            return true;
        }
        int nextCodePoint = nextWord.codePointAt(0);
        if (!CJK_RANGES.contains(nextCodePoint)) {
            return true;
        }
        /* Both are in CJK range, no space */
        return false;
    }
}
