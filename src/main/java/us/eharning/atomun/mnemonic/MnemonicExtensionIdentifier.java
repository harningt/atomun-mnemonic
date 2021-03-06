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

/**
 * Marker interface to declare a common base class for extension identifiers.
 * SPI implementors that have extensions are expected to provide these as enum values.
 *
 * @since 0.4.0
 */
public interface MnemonicExtensionIdentifier {
    /**
     * Whether or not this value can be read.
     * @return true if it can only be retrieved from MnemonicUnit.
     */
    boolean canGet();


    /**
     * Whether or or not this value can be set.
     * @return true if it can be set in MnemonicBuilder.
     */
    boolean canSet();
}
