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
package us.eharning.atomun.mnemonic.electrum

import com.google.common.base.Splitter
import spock.lang.Specification
import us.eharning.atomun.mnemonic.Mnemonic

/**
 * Created by harningt on 10/3/14.
 */
class ElectrumMnemonicSpockTest extends Specification {
    static Mnemonic electrumMnemonic = new ElectrumMnemonic()
    static String[][] pairs = [
            ["pleasure patience practice", "01234567"],
            ["pleasure patience practice offer jeans sister", "0123456789012345"],
            ["speak lunch group spring ring branch sign reflect cage slowly only carefully", "eeb15bed5a8ee524e254c5eab327c49c"],
            ["happen made spring knock heart middle suppose fish bought plain real ignore", "88c811176129b2882fc4737728195b87"],
            ["class group aside accept eat howl harm world ignorance brain count dude", "f9379762a6da83b4e40e31b682a6dd8d"]
    ]
    def "check #mnemonic string decodes to #encoded"() {
        expect:
            electrumMnemonic.decode(mnemonic) == hex.decodeHex()
        where:
            [ mnemonic, hex ] << pairs
    }
    def "check #mnemonic string iterable decodes to #encoded"() {
        expect:
            electrumMnemonic.decode(Splitter.on(' ').split(mnemonic)) == hex.decodeHex()
        where:
            [ mnemonic, hex ] << pairs
    }
    def "check #encoded encodes to #mnemonic"() {
        expect:
            Iterable<String> encoded = electrumMnemonic.encodeToIterable(hex.decodeHex())
            encoded != null
            encoded.join(' ') == mnemonic
        where:
            [ mnemonic, hex ] << pairs
    }
    def "mnemonic decoding of invalid too-short values throw"() {
        when:
            electrumMnemonic.decode("practice")
        then:
            thrown NoSuchElementException
    }
    def "mnemonic decoding with invalid dictionary words throw"() {
        when:
            electrumMnemonic.decode("practice practice FAILURE")
        then:
            thrown NoSuchElementException
    }

}
