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

package us.eharning.atomun.mnemonic.utility.dictionary

import com.google.common.io.ByteSource
import net.trajano.commons.testing.EqualsTestUtil
import net.trajano.commons.testing.UtilityClassTestUtil
import spock.lang.Shared
import spock.lang.Specification

/**
 * Tests covering MoreMnemonicExtensionIdentifiers operations.
 */
public class DictionarySpecification extends Specification {
    @Shared
    def englishLocation = "us/eharning/atomun/mnemonic/spi/electrum/v2/english.txt"
    @Shared
    def japaneseLocation = "us/eharning/atomun/mnemonic/spi/electrum/v2/japanese.txt"

    @Shared
    def englishIdentifier = DictionaryIdentifier.getIdentifier("english", englishLocation)
    @Shared
    def japaneseIdentifier = DictionaryIdentifier.getIdentifier("japanese", japaneseLocation)

    def "BidirectionalDictionarySource is a utility class"() {
        when:
        UtilityClassTestUtil.assertUtilityClassWellDefined(DictionarySource)
        then:
        noExceptionThrown()
    }

    def "attempting to convert an out-of-bounds integer fails"(int value) {
        given:
        def dict = DictionarySource.getDictionary(englishIdentifier)
        when:
        dict.convert(value)
        then:
        thrown(IllegalArgumentException)
        where:
        _ | value
        _ | -1
        _ | 1000000
        _ | Integer.MIN_VALUE
        _ | Integer.MAX_VALUE
    }

    def "a dictionary is self-equal"() {
        given:
        def dictA = DictionarySource.getDictionary(englishIdentifier)
        when:
        EqualsTestUtil.assertEqualsImplementedCorrectly(dictA)
        then:
        noExceptionThrown()
    }

    def "two fresh dictionaries identical in everything are equal"() {
        given:
        def dictA = DictionarySource.getFreshDictionary(englishIdentifier)
        def dictB = DictionarySource.getFreshDictionary(englishIdentifier)
        when:
        EqualsTestUtil.assertEqualsImplementedCorrectly(dictA, dictB)
        then:
        noExceptionThrown()
    }

    def "two dictionaries differing only in wordListIdentifier are not equal"() {
        given:
        def dictAIdentifier = englishIdentifier
        def dictBIdentifier = DictionaryIdentifier.getIdentifier("NOP", englishLocation)
        def dictA = DictionarySource.getDictionary(dictAIdentifier)
        def dictB = DictionarySource.getDictionary(dictBIdentifier)

        expect:
        dictA != dictB
        dictB != dictA
    }

    def "two dictionaries differing only in content are not equal"() {
        given:
        def dictAIdentifier = englishIdentifier
        def dictBIdentifier = DictionaryIdentifier.getIdentifier("english", japaneseLocation)
        def dictA = DictionarySource.getDictionary(dictAIdentifier)
        def dictB = DictionarySource.getDictionary(dictBIdentifier)

        expect:
        dictA != dictB
        dictB != dictA
    }

    def "two dictionaries completely different are not equal"() {
        given:
        def dictAIdentifier = englishIdentifier
        def dictBIdentifier = japaneseIdentifier
        def dictA = DictionarySource.getDictionary(dictAIdentifier)
        def dictB = DictionarySource.getDictionary(dictBIdentifier)

        expect:
        dictA != dictB
        dictB != dictA
    }


    def "two dictionary identifiers that are identical are equal"() {
        given:
        def dictAIdentifier = DictionaryIdentifier.getIdentifier("english", englishLocation)
        def dictBIdentifier = DictionaryIdentifier.getIdentifier("english", englishLocation)

        expect:
        EqualsTestUtil.assertEqualsImplementedCorrectly(dictAIdentifier)
        EqualsTestUtil.assertEqualsImplementedCorrectly(dictAIdentifier, dictBIdentifier)
    }

    def "two dictionary identifiers differing only in wordListIdentifier are not equal"() {
        given:
        def dictAIdentifier = englishIdentifier
        def dictBIdentifier = DictionaryIdentifier.getIdentifier("NOP", englishLocation)

        expect:
        dictAIdentifier != dictBIdentifier
        dictBIdentifier != dictAIdentifier
    }

    def "two dictionary identifiers differing only in content location are not equal"() {
        given:
        def dictAIdentifier = englishIdentifier
        def dictBIdentifier = DictionaryIdentifier.getIdentifier("english", japaneseLocation)

        expect:
        dictAIdentifier != dictBIdentifier
        dictBIdentifier != dictAIdentifier
    }

    def "two dictionary identifiers completely different are not equal"() {
        given:
        def dictAIdentifier = englishIdentifier
        def dictBIdentifier = japaneseIdentifier

        expect:
        dictAIdentifier != dictBIdentifier
        dictBIdentifier != dictAIdentifier
    }

    def "attempting to load a dictionary with a bad source will report argument exception"() {
        given:
        def badSource = new ByteSource() {
            @Override
            InputStream openStream() throws IOException {
                throw new IOException("Bogus")
            }
        }
        when:
        new Dictionary(badSource, englishIdentifier)
        then:
        thrown(IllegalArgumentException)
    }
}
