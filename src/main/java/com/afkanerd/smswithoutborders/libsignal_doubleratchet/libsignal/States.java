package com.afkanerd.smswithoutborders.libsignal_doubleratchet.libsignal;

import android.util.Log;
import android.util.Pair;

import androidx.annotation.Nullable;

import com.afkanerd.smswithoutborders.libsignal_doubleratchet.CryptoHelpers;
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.SecurityECDH;
import com.google.common.reflect.TypeToken;
import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.subtle.Bytes;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonSerializationContext;

import com.google.gson.JsonSerializer;

import org.json.JSONArray;
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

    public Map<Pair<PublicKey, Integer>, byte[]> MKSKIPPED = new HashMap<>();

    boolean valid = false;


    public States(KeyPair DHs, String states) throws JSONException, NoSuchAlgorithmException, InvalidKeySpecException {
        if(states == null)
            return;

        JSONObject jsonObject = new JSONObject(states);
        this.DHs = DHs;
        if(!jsonObject.getString("DHr").equals("null"))
            this.DHr = SecurityECDH.buildPublicKey(Base64.decode(jsonObject.getString("DHr"),
                    Base64.NO_WRAP));
        this.RK = Base64.decode(jsonObject.getString("RK"), Base64.NO_WRAP);
        this.CKs = Base64.decode(jsonObject.getString("CKs"), Base64.NO_WRAP);
        this.CKr = Base64.decode(jsonObject.getString("CKr"), Base64.NO_WRAP);
        this.Ns = jsonObject.getInt("Ns");
        this.Nr = jsonObject.getInt("Nr");
        this.PN = jsonObject.getInt("PN");

        JSONArray mkskipped = jsonObject.getJSONArray("MKSKIPPED");
        for(int i=0;i<mkskipped.length();++i) {
            JSONObject pair = mkskipped.getJSONObject(i);
            byte[] pubkey = Base64.decode(pair.getString(StatesMKSKIPPED.PUBLIC_KEY), Base64.NO_WRAP);
            this.MKSKIPPED.put(new Pair<>(SecurityECDH.buildPublicKey(pubkey),
                            pair.getInt(StatesMKSKIPPED.N)),
                    Base64.decode(pair.getString(StatesMKSKIPPED.MK), Base64.NO_WRAP));
        }
//        valid = true;
    }
    public static PublicKey getADForHeaders(States states, Headers headers) {
        for(Map.Entry<Pair<PublicKey, Integer>, byte[]> entry : states.MKSKIPPED.entrySet()) {
            if(entry.getKey().second == (headers.PN + headers.N))
                return entry.getKey().first;
        }

        return null;
    }

    public States() {
    }

    public String getSerializedStates() {
        GsonBuilder gsonBuilder = new GsonBuilder();
        gsonBuilder.registerTypeAdapter(KeyPair.class, new StatesKeyPairSerializer());
        gsonBuilder.registerTypeAdapter(PublicKey.class, new StatesPublicKeySerializer());
        gsonBuilder.registerTypeAdapter(byte[].class, new StatesBytesSerializer());
        gsonBuilder.registerTypeAdapter(Map.class, new StatesMKSKIPPED());
        gsonBuilder.setPrettyPrinting().serializeNulls();

        Gson gson = gsonBuilder.create();
        return gson.toJson(this);
    }

    @Override
    public boolean equals(@Nullable Object obj) {
        if(obj instanceof States) {
            States state = (States) obj;
//            return Objects.equals(state.DHs, this.DHs) &&
//                    Objects.equals(state.DHr, this.DHr) &&
//                    state.MKSKIPPED.equals(this.MKSKIPPED) &&
//                    Bytes.equal(state.RK, this.RK) &&
//                    Bytes.equal(state.CKr, this.CKr) &&
//                    Bytes.equal(state.CKs, this.CKs) &&
//                    state.Ns == this.Ns &&
//                    state.Nr == this.Nr &&
//                    state.PN == this.PN;
            return state.getSerializedStates().equals(this.getSerializedStates());
        }
        return false;
    }

    public static class StatesKeyPairSerializer implements JsonSerializer<KeyPair> {
        @Override
        public JsonElement serialize(KeyPair src, Type typeOfSrc, JsonSerializationContext context) {
            return new JsonPrimitive(
                    Base64.encodeToString(src.getPublic().getEncoded(), Base64.NO_WRAP));
        }
    }

    public static class StatesPublicKeySerializer implements JsonSerializer<PublicKey> {
        @Override
        public JsonElement serialize(PublicKey src, Type typeOfSrc, JsonSerializationContext context) {
            return new JsonPrimitive(Base64.encodeToString(src.getEncoded(), Base64.NO_WRAP));
        }
    }

    public static class StatesBytesSerializer implements JsonSerializer<byte[]> {
        @Override
        public JsonElement serialize(byte[] src, Type typeOfSrc, JsonSerializationContext context) {
            return new JsonPrimitive( Base64.encodeToString(src, Base64.NO_WRAP));
        }
    }


    public static class StatesMKSKIPPED implements JsonSerializer<Map<Pair<PublicKey, Integer>, byte[]>> {
        public final static String PUBLIC_KEY = "PUBLIC_KEY";
        public final static String N = "N";
        public final static String MK = "MK";

        @Override
        public JsonElement serialize(Map<Pair<PublicKey, Integer>, byte[]> src, Type typeOfSrc, JsonSerializationContext context) {
            JsonArray jsonArray = new JsonArray();
            for(Map.Entry<Pair<PublicKey, Integer>, byte[]> entry: src.entrySet()) {
                String publicKey = Base64.encodeToString(entry.getKey().first.getEncoded(), Base64.NO_WRAP);
                Integer n = entry.getKey().second;

                JsonObject jsonObject1 = new JsonObject();
                jsonObject1.addProperty(PUBLIC_KEY, publicKey);
                jsonObject1.addProperty(N, n);
                jsonObject1.addProperty(MK, Base64.encodeToString(entry.getValue(), Base64.NO_WRAP));

                jsonArray.add(jsonObject1);
            }
            return jsonArray;
        }
    }

}
