package com.afkanerd.smswithoutborders.libsignal_doubleratchet.libsignal;

import androidx.annotation.Nullable;

import com.afkanerd.smswithoutborders.libsignal_doubleratchet.SecurityECDH;
import com.google.common.primitives.Bytes;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

public class Headers {

    PublicKey dh;
    public int PN;
    public int N;

    public Headers(KeyPair dhPair, int PN, int N) {
        this.dh = dhPair.getPublic();
        this.PN = PN;
        this.N = N;
    }

    public Headers() {}

    public byte[] deSerializeHeader(byte[] serializedHeader) throws NoSuchAlgorithmException, InvalidKeySpecException,
            NumberFormatException{
        String header = new String(serializedHeader, StandardCharsets.UTF_8);
        String[] splitHeader = header.split(",");
        this.PN = Integer.parseInt(splitHeader[0]);
        this.N = Integer.parseInt(splitHeader[1]);
        this.dh = SecurityECDH.buildPublicKey(splitHeader[2].getBytes(StandardCharsets.UTF_8));

        splitHeader = Arrays.copyOfRange(splitHeader, 3, splitHeader.length);
        return String.join(",", splitHeader).getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public boolean equals(@Nullable Object obj) {
        if(obj instanceof Headers) {
            Headers header = (Headers) obj;
            return Arrays.equals(header.dh.getEncoded(), this.dh.getEncoded()) &&
                    header.PN == this.PN &&
                    header.N == this.N;
        }
        return false;
    }

    public byte[] getSerialized(){
        byte[] values = (PN + "," + N + ",").getBytes();
        return Bytes.concat(values, dh.getEncoded(), ",".getBytes(StandardCharsets.UTF_8));
    }
}
