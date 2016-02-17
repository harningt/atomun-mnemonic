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

import com.google.common.base.Objects;

import javax.annotation.Nonnull;
import javax.annotation.concurrent.Immutable;

/**
 * Identifier for use in dictionary lookup.
 */
@Immutable
public final class DictionaryIdentifier {
    private final String name;
    private final String resourceName;

    /**
     * Construct an identifier referenced by the given name and resource location.
     *
     * @param name
     *          wordList name of the dictionary.
     * @param resourceName
     *          location to retrieve the dictionary.
     *
     * @return
     *          identifier for the given dictionary.
     */
    private DictionaryIdentifier(@Nonnull String name, @Nonnull String resourceName) {
        this.name = name;
        this.resourceName = resourceName;
    }

    /**
     * Get an identifier referenced by the given name and resource location.
     *
     * @param name
     *          name of the dictionary.
     * @param resourceName
     *          location to retrieve the dictionary.
     *
     * @return
     *          identifier for the given dictionary.
     */
    public static DictionaryIdentifier getIdentifier(@Nonnull String name, @Nonnull String resourceName) {
        return new DictionaryIdentifier(checkNotNull(name), checkNotNull(resourceName));
    }

    /**
     * Get the name of the dictionary.
     *
     * @return dictionary name.
     */
    @Nonnull
    public final String getName() {
        return name;
    }

    /**
     * Get the location of the dictionary.
     *
     * @return dictionary location.
     */
    @Nonnull
    public final String getResourceName() {
        return resourceName;
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (other == null || getClass() != other.getClass()) {
            return false;
        }
        DictionaryIdentifier that = (DictionaryIdentifier) other;
        return Objects.equal(name, that.name)
                && Objects.equal(resourceName, that.resourceName);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(name, resourceName);
    }
}
