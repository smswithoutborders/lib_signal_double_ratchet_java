package com.afkanerd.smswithoutborders.libsignal_doubleratchet.libsignal;

import android.util.Pair;

import androidx.annotation.Nullable;

import com.google.crypto.tink.subtle.Base64;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class States {
    public KeyPair DHs;
    public PublicKey DHr;

    public byte[] RK;
    public byte[] CKs;
    public byte[] CKr;

    public int Ns = 0;

    public int Nr = 0;

    public int PN = 0;

    Map<Pair<PublicKey, Integer>, byte[]> MKSKIPPED = new HashMap<>();

    @Override
    public boolean equals(@Nullable Object obj) {
        if(obj instanceof States) {
            States state = (States) obj;
            return (
                    (state.DHr != null && this.DHr != null &&
                            Arrays.equals(state.DHr.getEncoded(), this.DHr.getEncoded()))
                    || Objects.equals(state.DHr, this.DHr)) &&
                    state.MKSKIPPED.equals(this.MKSKIPPED) &&
                    state.Ns == this.Ns &&
                    state.Nr == this.Nr &&
                    state.PN == this.PN;
        }
        return false;
    }

    public String log(String name) {
        return name + " - DHs: " + Base64.encodeToString(DHs.getPublic().getEncoded(), Base64.DEFAULT) + "\n" +
                name + " - DHr: " + Base64.encodeToString(DHr.getEncoded(), Base64.DEFAULT) + "\n" +
                name + " - RK: " + Base64.encodeToString(RK, Base64.DEFAULT) + "\n" +
                name + " - CKs: " + Base64.encodeToString(CKs, Base64.DEFAULT) + "\n" +
                name + " - CKr: " + Base64.encodeToString(CKr, Base64.DEFAULT) + "\n" +
                name + " - Ns: " + Ns + "\n" +
                name + " - Nr: " + Nr + "\n" +
                name + " - PN: " + PN;
    }
}
