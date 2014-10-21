/*
 * Copyright 2014 Thomas Harning Jr. <harningt@gmail.com>
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
 * Interface wrapping a mnemonic codec.
 */
public interface Mnemonic {

    /**
     * Encode a sequence of bytes to its series of mnemonic words.
     * @param data value to encode.
     * @return sequence of mnemonic words.
     */
    Iterable<String> encodeToIterable(byte[] data);

    /**
     * Encode a sequence of bytes to a space-delimited series of mnemonic words.
     * @param data value to encode.
     * @return space-delimited sequence of mnemonic words.
     */
    String encodeToString(byte[] data);

    /**
     * Decode a space-delimited sequence of mnemonic words.
     * @param words space-delimited sequence of mnemonic words to decode.
     * @return encoded value.
     */
    byte[] decode(CharSequence words);

    /**
     * Decode a sequence of mnemonic words.
     * @param words sequence of mnemonic words to decode.
     * @return encoded value.
     */
    byte[] decode(Iterable<String> words);
}
