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

package us.eharning.atomun.mnemonic.spi.electrum.v2;

import java.util.Arrays;

/**
 * Enumeration encapsulating the known version prefix values.
 */
public enum VersionPrefix {
    STANDARD(new byte[]{0x01}, new byte[]{(byte) 0xFF});

    private final byte[] value;
    private final byte[] valueMask;

    VersionPrefix(byte[] value, byte[] valueMask) {
        this.value = value;
        this.valueMask = valueMask;
    }

    public byte[] getValue() {
        return Arrays.copyOf(value, value.length);
    }
    public byte[] getValueMask() {
        return Arrays.copyOf(valueMask, valueMask.length);
    }

    public int getValueBitLength() {
        /* TODO: Count last bit used by mask */
        return value.length * 8;
    }

    public boolean matches(byte[] data) {
        /* Check the mask bytes */
        if (value.length > data.length) {
            return false;
        }
        for (int i = 0; i < value.length; i++) {
            /* NOTE: mask presumed to already be applied to prefix */
            if (value[i] != (valueMask[i] & data[i])) {
                return false;
            }
        }
        return true;
    }
}
