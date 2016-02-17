/*
 * Copyright 2016 Thomas Harning Jr. <harningt@gmail.com>
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

import com.google.common.base.Function;
import com.google.common.base.Throwables;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.io.ByteSource;
import com.google.common.io.Resources;
import com.google.common.util.concurrent.UncheckedExecutionException;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

import java.net.URL;
import javax.annotation.Nullable;

/**
 * Manages access to data used, such as word lists.
 */
public final class DictionarySource {
    /*
     * Loader instance - note not final to permit testing.
     */
    private static Function<DictionaryIdentifier, Dictionary> loader = getCachingLoader();

    /**
     * Mark constructor as private due to it being a singleton.
     */
    private DictionarySource() {
    }

    /**
     * Get an instance of a dictionary.
     *
     * @param identifier
     *          identifier to load the dictionary for.
     *
     * @return dictionary instance
     */
    public static Dictionary getDictionary(DictionaryIdentifier identifier) {
        try {
            return loader.apply(identifier);
        } catch (UncheckedExecutionException e) {
            /* Rethrow the cause of the execution exception
             * as with the case of a cache failure.
             */
            throw Throwables.propagate(e.getCause());
        }
    }

    /**
     * Get an fresh instance of a dictionary with no caching.
     *
     * @param identifier
     *          identifier to load the dictionary for.
     *
     * @return dictionary instance
     */
    static Dictionary getFreshDictionary(DictionaryIdentifier identifier) {
        return SimpleLoader.INSTANCE.apply(identifier);
    }

    /**
     * Basic loader that directly loads a dictionary from a Java resource.
     */
    private static class SimpleLoader implements Function<DictionaryIdentifier, Dictionary> {
        /**
         * Utility singleton instance for internal use.
         */
        static final SimpleLoader INSTANCE = new SimpleLoader();

        /**
         * Load the dictionary for the given identifier.
         *
         * @param input
         *          identifier to construct dictionary for.
         * @return
         *          constructed dictionary.
         */
        @SuppressFBWarnings("NP_PARAMETER_MUST_BE_NONNULL_BUT_MARKED_AS_NULLABLE")
        @Nullable
        @Override
        public Dictionary apply(@Nullable DictionaryIdentifier input) {
            checkNotNull(input);
            URL url = Resources.getResource(input.getResourceName());
            ByteSource source = Resources.asByteSource(url);
            return new Dictionary(source, input);
        }
    }

    private static Function<DictionaryIdentifier, Dictionary> getCachingLoader() {
        return CacheBuilder.newBuilder()
                .build(new CacheLoader<DictionaryIdentifier, Dictionary>() {
                    @Override
                    public Dictionary load(DictionaryIdentifier key) throws Exception {
                        return SimpleLoader.INSTANCE.apply(key);
                    }
                });
    }
}
