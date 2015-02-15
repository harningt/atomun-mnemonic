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

import com.google.common.collect.ImmutableMap;

import javax.annotation.Nonnull;
import javax.annotation.concurrent.Immutable;
import java.util.Map;

/**
 * Builder parameter representing list of named extension values.
 *
 * @since 0.1.0
 */
@Immutable
public class ExtensionBuilderParameter implements BuilderParameter {
    private final ImmutableMap<String, Object> extensions;

    private ExtensionBuilderParameter(@Nonnull ImmutableMap<String, Object> extensions) {
        this.extensions = extensions;
    }

    @Nonnull
    public Map<String, Object> getExtensions() {
        return extensions;
    }

    @Nonnull
    public static ExtensionBuilderParameter getExtensionsParameter(@Nonnull ImmutableMap<String, Object> extensions) {
        return new ExtensionBuilderParameter(extensions);
    }
}
