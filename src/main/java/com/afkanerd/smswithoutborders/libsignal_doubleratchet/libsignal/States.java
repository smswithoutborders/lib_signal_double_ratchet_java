package com.afkanerd.smswithoutborders.libsignal_doubleratchet.libsignal;

import android.util.Pair;

import androidx.annotation.Nullable;

import com.afkanerd.smswithoutborders.libsignal_doubleratchet.CryptoHelpers;
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.SecurityECDH;
import com.google.crypto.tink.subtle.Base64;
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

    GsonBuilder gsonBuilder = new GsonBuilder();

    static {
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

    public static class StateKeysSerializer implements JsonSerializer<KeyPair> {

        @Override
        public JsonElement serialize(KeyPair src, Type typeOfSrc, JsonSerializationContext context) {
            return new JsonPrimitive(
                    Base64.encodeToString(src.getPublic().getEncoded(), Base64.DEFAULT));
        }
    }

    public States(KeyPair DHs,
                  PublicKey DHr,
                  byte[] RK, byte[] CKs, byte[] CKr,
                  int Ns, int Nr, int PN) {
        this.DHs = DHs;
        this.DHr = DHr;
        this.RK = RK;
        this.CKs = CKs;
        this.CKr = CKr;
        this.Ns = Ns;
        this.Nr = Nr;
        this.PN= PN;
    }

    public States(String states) throws JSONException, NoSuchAlgorithmException, InvalidKeySpecException {
        JSONObject jsonObject = new JSONObject(states);
        this.DHr = SecurityECDH.buildPublicKey(Base64.decode(jsonObject.getString("DHr"),
                Base64.DEFAULT));
        this.RK = Base64.decode(jsonObject.getString("DHs"), Base64.DEFAULT);
        this.CKs = Base64.decode(jsonObject.getString("CKs"), Base64.DEFAULT);
        this.CKr = Base64.decode(jsonObject.getString("CKr"), Base64.DEFAULT);
        this.Ns = jsonObject.getInt("Ns");
        this.Nr = jsonObject.getInt("Nr");
        this.PN = jsonObject.getInt("PN");
    }

    public States() {
    }

    public String getSerializedStates() {
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
