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
package us.eharning.atomun.mnemonic.spi.bip0039

import com.google.common.base.Charsets
import groovy.json.JsonSlurper
import groovy.transform.Canonical

import java.text.Normalizer

/**
 * Container for common BIP0039 test data.
 */
class BIP0039TestData {
    @Canonical
    static class MnemonicTestCase {
        String wordList;
        String mnemonic;

        public String getNormalizedMnemonic() {
            return Normalizer.normalize(mnemonic, Normalizer.Form.NFKD);
        }
        public String passphrase;
        public String entropy;

        public byte[] getEntropyBytes() {
            return entropy.decodeHex();
        }
        public String seed;

        public byte[] getSeedBytes() {
            return seed.decodeHex();
        }
        public String bip32_xprv;
    }
    private static final String TREZOR_OFFICIAL_PASSWORD = "TREZOR"
    public static final Iterable<MnemonicTestCase> TREZOR_OFFICIAL_VECTORS
    public static final Iterable<MnemonicTestCase> JP_VECTORS

    private static Object parseResource(String resourceName) {
        InputStream input = BIP0039MnemonicBuilderSpock.class.classLoader.getResourceAsStream(resourceName)
        return new JsonSlurper().parse(new InputStreamReader(input, Charsets.UTF_8));
    }

    static {
        TREZOR_OFFICIAL_VECTORS = parseResource("us/eharning/atomun/mnemonic/spi/bip0039/BIP0039_TREZOR_VECTORS.json").collectMany {
            String wordList = it.key
            return it.value.collect { test ->
                return [wordList: wordList, mnemonic: test[1], entropy: test[0], seed: test[2], passphrase: TREZOR_OFFICIAL_PASSWORD] as MnemonicTestCase
            }
        }
        JP_VECTORS = parseResource("us/eharning/atomun/mnemonic/spi/bip0039/BIP0039-test_JP.json").collect {
            MnemonicTestCase testCase = it as MnemonicTestCase
            testCase.wordList = "japanese"
            return testCase
        }
    }
}
