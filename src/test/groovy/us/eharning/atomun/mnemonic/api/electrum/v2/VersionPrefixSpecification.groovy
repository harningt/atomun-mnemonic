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

package us.eharning.atomun.mnemonic.api.electrum.v2

import spock.lang.Specification

/**
 * Builder SPI tests
 */
class VersionPrefixSpecification extends Specification {
    def "Each prefix has a retrievable value and mask"(VersionPrefix prefix) {
        expect:
        prefix.value != null
        prefix.valueMask != null
        where:
        prefix << Arrays.asList(VersionPrefix.values())
    }

    def "Each prefix has a non-empty equal-length value and mask"(VersionPrefix prefix) {
        expect:
        prefix.value.length > 0
        prefix.valueMask.length > 0
        prefix.value.length == prefix.valueMask.length
        where:
        prefix << Arrays.asList(VersionPrefix.values())
    }

    def "Identity matches should all pass"(VersionPrefix prefix) {
        given:
        byte[] data = prefix.value
        expect:
        prefix.matches(data)
        where:
        prefix << Arrays.asList(VersionPrefix.values())
    }

    private static byte[] getInverted(byte[] data) {
        data = Arrays.copyOf(data, data.length)
        for (int i = 0; i < data.length; i++) {
            data[i] = ~data[i]
        }
        return data
    }

    def "Inverted matches should all fail"(VersionPrefix prefix) {
        given:
        byte[] data = getInverted(prefix.value)
        expect:
        !prefix.matches(data)
        where:
        prefix << Arrays.asList(VersionPrefix.values())
    }


    def "Short-length matches should never match"(VersionPrefix prefix) {
        given:
        byte[] data = Arrays.copyOf(prefix.value, prefix.value.length - 1)
        expect:
        !prefix.matches(data)
        where:
        prefix << Arrays.asList(VersionPrefix.values())
    }

    def "Zero-length strings should never match"(VersionPrefix prefix) {
        given:
        byte[] data = new byte[0]
        expect:
        !prefix.matches(data)
        where:
        prefix << Arrays.asList(VersionPrefix.values())
    }
}
