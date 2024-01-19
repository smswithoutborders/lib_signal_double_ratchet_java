package com.afkanerd.smswithoutborders.libsignal_doubleratchet.libsignal;

import android.util.Log;
import android.util.Pair;

import androidx.annotation.Nullable;

import com.afkanerd.smswithoutborders.libsignal_doubleratchet.CryptoHelpers;
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.SecurityECDH;
import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.subtle.Bytes;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;

import org.json.JSONException;
import org.json.JSONObject;

import java.lang.reflect.Type;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class States {
    public KeyPair DHs;
    // Important: store this separate

    public PublicKey DHr;

    public byte[] RK;
    public byte[] CKs;
    public byte[] CKr;

    public int Ns = 0;

    public int Nr = 0;

    public int PN = 0;

    Map<Pair<PublicKey, Integer>, byte[]> MKSKIPPED = new HashMap<>();

    boolean valid = false;

    public States(KeyPair DHs, String states) throws JSONException, NoSuchAlgorithmException, InvalidKeySpecException {
        if(states == null)
            return;

        JSONObject jsonObject = new JSONObject(states);
        this.DHs = DHs;
        if(!jsonObject.getString("DHr").equals("null"))
            this.DHr = SecurityECDH.buildPublicKey(Base64.decode(jsonObject.getString("DHr"),
                    Base64.DEFAULT));
        this.RK = Base64.decode(jsonObject.getString("RK"), Base64.DEFAULT);
        this.CKs = Base64.decode(jsonObject.getString("CKs"), Base64.DEFAULT);
        this.CKr = Base64.decode(jsonObject.getString("CKr"), Base64.DEFAULT);
        this.Ns = jsonObject.getInt("Ns");
        this.Nr = jsonObject.getInt("Nr");
        this.PN = jsonObject.getInt("PN");
        valid = true;
    }

    public States() {
    }

    public String getSerializedStates() {
        GsonBuilder gsonBuilder = new GsonBuilder();
        gsonBuilder.registerTypeAdapter(KeyPair.class, new StatesKeyPairSerializer());
        gsonBuilder.registerTypeAdapter(PublicKey.class, new StatesPublicKeySerializer());
        gsonBuilder.registerTypeAdapter(byte[].class, new StatesBytesSerializer());
        gsonBuilder.setPrettyPrinting().serializeNulls();

        Gson gson = gsonBuilder.create();
        return gson.toJson(this);
    }

    @Override
    public boolean equals(@Nullable Object obj) {
        if(obj instanceof States) {
            States state = (States) obj;
            return (
                    (state.DHr != null && this.DHr != null &&
                            Arrays.equals(state.DHr.getEncoded(), this.DHr.getEncoded()))
                    || Objects.equals(state.DHr, this.DHr)) &&
                    state.MKSKIPPED.equals(this.MKSKIPPED) &&
                    Bytes.equal(state.RK, this.RK) &&
                    Bytes.equal(state.CKr, this.CKr) &&
                    Bytes.equal(state.CKs, this.CKs) &&
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

    public static class StatesKeyPairSerializer implements JsonSerializer<KeyPair> {
        @Override
        public JsonElement serialize(KeyPair src, Type typeOfSrc, JsonSerializationContext context) {
            return new JsonPrimitive(
                    Base64.encodeToString(src.getPublic().getEncoded(), Base64.DEFAULT));
        }
    }

    public static class StatesPublicKeySerializer implements JsonSerializer<PublicKey> {
        @Override
        public JsonElement serialize(PublicKey src, Type typeOfSrc, JsonSerializationContext context) {
            return new JsonPrimitive(Base64.encodeToString(src.getEncoded(), Base64.DEFAULT));
        }
    }

    public static class StatesBytesSerializer implements JsonSerializer<byte[]> {
        @Override
        public JsonElement serialize(byte[] src, Type typeOfSrc, JsonSerializationContext context) {
            return new JsonPrimitive( Base64.encodeToString(src, Base64.DEFAULT));
        }
    }

}
