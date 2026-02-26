package com.afkanerd.smswithoutborders.libsignal_doubleratchet.libsignal;

import android.util.Log;
import android.util.Pair;
import android.util.Base64;

import androidx.annotation.Nullable;

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

public class States {
    public Pair<byte[], byte[]> DHs;
    public byte[] DHr;
    public byte[] RK;
    public byte[] CKs;
    public byte[] CKr;

    public int Ns = 0;
    public int Nr = 0;
    public int PN = 0;

    public Map<Pair<byte[], Integer>, byte[]> MKSKIPPED = new HashMap<>();

    public States(String states) throws JSONException {
        if(states == null)
            return;

        JSONObject jsonObject = new JSONObject(states);
        if(jsonObject.has("DHs")) {
            String[] encodedValues = jsonObject.getString("DHs").split(" ");
            this.DHs = new Pair<>(android.util.Base64.decode(encodedValues[0], Base64.NO_WRAP),
                    android.util.Base64.decode(encodedValues[1], Base64.NO_WRAP));
        }
        if(jsonObject.has("DHr"))
            this.DHr = Base64.decode(jsonObject.getString("DHr"), Base64.NO_WRAP);

        if(jsonObject.has("RK"))
            this.RK = Base64.decode(jsonObject.getString("RK"), Base64.NO_WRAP);
        if(jsonObject.has("CKs"))
            this.CKs = Base64.decode(jsonObject.get("CKs").toString(), Base64.NO_WRAP);
        if(jsonObject.has("CKr"))
            this.CKr = Base64.decode(jsonObject.getString("CKr"), Base64.NO_WRAP);
        this.Ns = jsonObject.getInt("Ns");
        this.Nr = jsonObject.getInt("Nr");
        this.PN = jsonObject.getInt("PN");

        JSONArray mkskipped = jsonObject.getJSONArray("MKSKIPPED");
        for(int i=0;i<mkskipped.length();++i) {
            JSONObject pair = mkskipped.getJSONObject(i);
            byte[] pubkey = Base64.decode(pair.getString(StatesMKSKIPPED.PUBLIC_KEY), Base64.NO_WRAP);
            this.MKSKIPPED.put(new Pair<>(pubkey, pair.getInt(StatesMKSKIPPED.N)),
                    Base64.decode(pair.getString(StatesMKSKIPPED.MK), Base64.NO_WRAP));
        }
    }

    public static byte[] getADForHeaders(States states, Headers headers) {
        for(Map.Entry<Pair<byte[], Integer>, byte[]> entry : states.MKSKIPPED.entrySet()) {
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
        gsonBuilder.registerTypeAdapter(Pair.class, new PairStatesBytesSerializer());
        gsonBuilder.registerTypeAdapter(Map.class, new StatesMKSKIPPED());
        gsonBuilder.setPrettyPrinting()
                .disableHtmlEscaping();

        Gson gson = gsonBuilder.create();
        return gson.toJson(this);
    }

    @Override
    public boolean equals(@Nullable Object obj) {
        if(obj instanceof States state) {
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

    public static class PairStatesBytesSerializer implements JsonSerializer<Pair<byte[], byte[]>> {
        @Override
        public JsonElement serialize(Pair<byte[], byte[]> src, Type typeOfSrc, JsonSerializationContext context) {
            return new JsonPrimitive( Base64.encodeToString(src.first, Base64.NO_WRAP) + " " +
                    Base64.encodeToString(src.second, Base64.NO_WRAP));
        }
    }

    public static class StatesBytesSerializer implements JsonSerializer<byte[]> {
        @Override
        public JsonElement serialize(byte[] src, Type typeOfSrc, JsonSerializationContext context) {
            return new JsonPrimitive( Base64.encodeToString(src, Base64.NO_WRAP));
        }
    }


    public static class StatesMKSKIPPED implements JsonSerializer<Map<Pair<byte[], Integer>, byte[]>> {
        public final static String PUBLIC_KEY = "PUBLIC_KEY";
        public final static String N = "N";
        public final static String MK = "MK";

        @Override
        public JsonElement serialize(Map<Pair<byte[], Integer>, byte[]> src, Type typeOfSrc, JsonSerializationContext context) {
            JsonArray jsonArray = new JsonArray();
            for(Map.Entry<Pair<byte[], Integer>, byte[]> entry: src.entrySet()) {
                String publicKey = Base64.encodeToString(entry.getKey().first, Base64.NO_WRAP);
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
