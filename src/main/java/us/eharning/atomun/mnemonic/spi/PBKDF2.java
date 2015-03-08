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

import static java.lang.System.arraycopy;

import com.google.common.annotations.Beta;

import java.security.GeneralSecurityException;
import javax.annotation.ParametersAreNonnullByDefault;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Internal implementation of PBKDF2 layered atop standard primitives for more flexibility.
 */
@Beta
@ParametersAreNonnullByDefault
public final class PBKDF2 {
    /**
     * Implementation of PBKDF2 (RFC2898).
     *
     * @param alg
     *         HMAC algorithm to use.
     * @param P
     *         Password.
     * @param S
     *         Salt.
     * @param c
     *         Iteration count.
     * @param dkLen
     *         Intended length, in octets, of the derived key.
     *
     * @return The derived key.
     *
     * @throws GeneralSecurityException
     */
    @SuppressWarnings({"checkstyle:parametername", "checkstyle:localvariablename"})
    public static byte[] pbkdf2(String alg, byte[] P, byte[] S, int c, int dkLen) throws GeneralSecurityException {
        Mac mac = Mac.getInstance(alg);
        mac.init(new SecretKeySpec(P, alg));
        byte[] DK = new byte[dkLen];
        pbkdf2(mac, S, c, DK, dkLen);
        return DK;
    }

    /**
     * Implementation of PBKDF2 (RFC2898).
     *
     * @param mac
     *         Pre-initialized {@link Mac} instance to use.
     * @param S
     *         Salt.
     * @param c
     *         Iteration count.
     * @param DK
     *         Byte array that derived key will be placed in.
     * @param dkLen
     *         Intended length, in octets, of the derived key.
     *
     * @throws GeneralSecurityException
     */
    @SuppressWarnings({"checkstyle:parametername", "checkstyle:localvariablename"})
    public static void pbkdf2(Mac mac, byte[] S, int c, byte[] DK, int dkLen) throws GeneralSecurityException {
        int hLen = mac.getMacLength();

        if (dkLen > (Math.pow(2, 32) - 1) * hLen) {
            throw new GeneralSecurityException("Requested key length too long");
        }

        byte[] U = new byte[hLen];
        byte[] T = new byte[hLen];
        byte[] block1 = new byte[S.length + 4];

        int l = (int) Math.ceil((double) dkLen / hLen);
        int r = dkLen - (l - 1) * hLen;

        arraycopy(S, 0, block1, 0, S.length);

        for (int i = 1; i <= l; i++) {
            block1[S.length + 0] = (byte) (i >> 24 & 0xff);
            block1[S.length + 1] = (byte) (i >> 16 & 0xff);
            block1[S.length + 2] = (byte) (i >> 8 & 0xff);
            block1[S.length + 3] = (byte) (i >> 0 & 0xff);

            mac.update(block1);
            mac.doFinal(U, 0);
            arraycopy(U, 0, T, 0, hLen);

            for (int j = 1; j < c; j++) {
                mac.update(U);
                mac.doFinal(U, 0);

                for (int k = 0; k < hLen; k++) {
                    T[k] ^= U[k];
                }
            }

            arraycopy(T, 0, DK, (i - 1) * hLen, (i == l ? r : hLen));
        }
    }
}