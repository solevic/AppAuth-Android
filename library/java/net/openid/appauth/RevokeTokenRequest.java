/*
 * Copyright 2021 The AppAuth for Android Authors. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the
 * License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.openid.appauth;

import static net.openid.appauth.AdditionalParamsProcessor.checkAdditionalParams;
import static net.openid.appauth.Preconditions.checkNotEmpty;
import static net.openid.appauth.Preconditions.checkNotNull;

import android.net.Uri;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.VisibleForTesting;

import org.json.JSONException;
import org.json.JSONObject;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * An OAuth2 token revocation request. The request is used to revoke both refresh and access tokens.
 *
 * @see "OAuth 2.0 Token Revocation (RFC 7009), Section 2.1
 * <https://datatracker.ietf.org/doc/html/rfc7009#section-2.1>"
 */
public class RevokeTokenRequest {

    @VisibleForTesting
    static final String KEY_CONFIGURATION = "configuration";
    @VisibleForTesting
    static final String KEY_CLIENT_ID = "clientId";
    @VisibleForTesting
    static final String KEY_TOKEN_TYPE_HINT = "tokenTypeHint";
    @VisibleForTesting
    static final String KEY_TOKEN = "token";
    @VisibleForTesting
    static final String KEY_ADDITIONAL_PARAMETERS = "additionalParameters";

    public static final String PARAM_CLIENT_ID = "client_id";

    @VisibleForTesting
    static final String PARAM_TOKEN = "token";

    @VisibleForTesting
    static final String PARAM_TOKEN_TYPE_HINT = "token_type_hint";

    private static final Set<String> BUILT_IN_PARAMS = Collections.unmodifiableSet(
            new HashSet<>(Arrays.asList(
                    PARAM_CLIENT_ID,
                    PARAM_TOKEN,
                    PARAM_TOKEN_TYPE_HINT)));

    /**
     * The token type used to revoke an access token.
     *
     * @see "OAuth 2.0 Token Revocation (RFC 7009), Section 2.1
     * <https://datatracker.ietf.org/doc/html/rfc7009#section-2.1>"
     */
    public static final String TOKEN_TYPE_ACCESS = "access_token";

    /**
     * The token type used to revoke a refresh token.
     *
     * @see "OAuth 2.0 Token Revocation (RFC 7009), Section 2.1
     * <https://datatracker.ietf.org/doc/html/rfc7009#section-2.1>"
     */
    public static final String TOKEN_TYPE_REFRESH = "refresh_token";

    /**
     * The service's {@link AuthorizationServiceConfiguration configuration}.
     * This configuration specifies how to connect to a particular OAuth provider.
     * Configurations may be
     * {@link
     * AuthorizationServiceConfiguration#AuthorizationServiceConfiguration(Uri, Uri, Uri, Uri)
     * created manually}, or
     * {@link AuthorizationServiceConfiguration#fetchFromUrl(Uri,
     * AuthorizationServiceConfiguration.RetrieveConfigurationCallback)
     * via an OpenID Connect Discovery Document}.
     */
    @NonNull
    public final AuthorizationServiceConfiguration configuration;

    /**
     * The client identifier.
     *
     * @see "The OAuth 2.0 Authorization Framework (RFC 6749), Section 4
     * <https://tools.ietf.org/html/rfc6749#section-4>"
     * @see "The OAuth 2.0 Authorization Framework (RFC 6749), Section 4.1.1
     * <https://tools.ietf.org/html/rfc6749#section-4.1.1>"
     */
    @NonNull
    public final String clientId;

    /**
     * The (optional) token type hint of the token to revoke.
     *
     * @see "OAuth 2.0 Token Revocation (RFC 7009), Section 2.1
     * <https://datatracker.ietf.org/doc/html/rfc7009#section-2.1>"
     */
    @Nullable
    public final String tokenTypeHint;

    /**
     * The token to be revoked.
     *
     * @see "OAuth 2.0 Token Revocation (RFC 7009), Section 2.1
     * <https://datatracker.ietf.org/doc/html/rfc7009#section-2.1>"
     */
    @NonNull
    public final String token;

    /**
     * Additional parameters to be passed as part of the request.
     */
    @NonNull
    public final Map<String, String> additionalParameters;

    /**
     * Creates instances of {@link RevokeTokenRequest}.
     */
    public static final class Builder {

        @NonNull
        private AuthorizationServiceConfiguration mConfiguration;

        @NonNull
        private String mClientId;

        @Nullable
        private String mTokenTypeHint;

        @NonNull
        private String mToken;

        @NonNull
        private Map<String, String> mAdditionalParameters;

        /**
         * Creates a token revocation request builder with the specified mandatory properties.
         */
        public Builder(
                @NonNull AuthorizationServiceConfiguration configuration,
                @NonNull String clientId,
                @NonNull String token) {
            setConfiguration(configuration);
            setClientId(clientId);
            setToken(token);
            mAdditionalParameters = new LinkedHashMap<>();
        }

        /**
         * Specifies the authorization service configuration for the request, which must not
         * be null or empty.
         */
        @NonNull
        public Builder setConfiguration(@NonNull AuthorizationServiceConfiguration configuration) {
            mConfiguration = checkNotNull(configuration);
            return this;
        }

        /**
         * Specifies the client ID for the token revocation request, which must not be null or
         * empty.
         */
        @NonNull
        public Builder setClientId(@NonNull String clientId) {
            mClientId = checkNotEmpty(clientId, "clientId cannot be null or empty");
            return this;
        }

        /**
         * Specifies the (optional) token type hint for the token to revoke.
         */
        @NonNull
        public Builder setTokenTypeHint(@Nullable String tokenTypeHint) {
            mTokenTypeHint = tokenTypeHint;
            return this;
        }

        /**
         * Specifies the token to be revoked.
         */
        @NonNull
        public Builder setToken(@NonNull String token) {
            mToken = checkNotEmpty(token, "token cannot be null or empty");;
            return this;
        }

        /**
         * Specifies an additional set of parameters to be sent as part of the request.
         */
        @NonNull
        public Builder setAdditionalParameters(@Nullable Map<String, String> additionalParameters) {
            mAdditionalParameters = checkAdditionalParams(additionalParameters, BUILT_IN_PARAMS);
            return this;
        }

        /**
         * Produces a {@link RevokeTokenRequest} instance.
         */
        @NonNull
        public RevokeTokenRequest build() {
            return new RevokeTokenRequest(
                    mConfiguration,
                    mClientId,
                    mTokenTypeHint,
                    mToken,
                    Collections.unmodifiableMap(mAdditionalParameters));
        }
    }

    private RevokeTokenRequest(
            @NonNull AuthorizationServiceConfiguration configuration,
            @NonNull String clientId,
            @Nullable String tokenTypeHint,
            @NonNull String token,
            @NonNull Map<String, String> additionalParameters) {
        this.configuration = configuration;
        this.clientId = clientId;
        this.tokenTypeHint = tokenTypeHint;
        this.token = token;
        this.additionalParameters = additionalParameters;
    }

    /**
     * Produces the set of request parameters for this query, which can be further
     * processed into a request body.
     */
    @NonNull
    public Map<String, String> getRequestParameters() {
        Map<String, String> params = new HashMap<>();
        params.put(PARAM_TOKEN, token);
        putIfNotNull(params, PARAM_TOKEN_TYPE_HINT, tokenTypeHint);

        for (Map.Entry<String, String> param : additionalParameters.entrySet()) {
            params.put(param.getKey(), param.getValue());
        }

        return params;
    }

    private void putIfNotNull(Map<String, String> map, String key, Object value) {
        if (value != null) {
            map.put(key, value.toString());
        }
    }

    /**
     * Produces a JSON string representation of the token revocation request for persistent storage
     * or local transmission (e.g. between activities).
     */
    @NonNull
    public JSONObject jsonSerialize() {
        JSONObject json = new JSONObject();
        JsonUtil.put(json, KEY_CONFIGURATION, configuration.toJson());
        JsonUtil.put(json, KEY_CLIENT_ID, clientId);
        JsonUtil.putIfNotNull(json, KEY_TOKEN_TYPE_HINT, tokenTypeHint);
        JsonUtil.put(json, KEY_TOKEN, token);
        JsonUtil.put(json, KEY_ADDITIONAL_PARAMETERS,
                JsonUtil.mapToJsonObject(additionalParameters));
        return json;
    }

    /**
     * Produces a JSON string representation of the token revocation request for persistent storage
     * or local transmission (e.g. between activities). This method is just a convenience wrapper
     * for {@link #jsonSerialize()}, converting the JSON object to its string form.
     */
    @NonNull
    public String jsonSerializeString() {
        return jsonSerialize().toString();
    }

    /**
     * Reads a token revocation request from a JSON string representation produced by
     * {@link #jsonSerialize()}.
     * @throws JSONException if the provided JSON does not match the expected structure.
     */
    @NonNull
    public static RevokeTokenRequest jsonDeserialize(JSONObject json) throws JSONException {
        checkNotNull(json, "json object cannot be null");

        return new RevokeTokenRequest(
                AuthorizationServiceConfiguration.fromJson(json.getJSONObject(KEY_CONFIGURATION)),
                JsonUtil.getString(json, KEY_CLIENT_ID),
                JsonUtil.getStringIfDefined(json, KEY_TOKEN_TYPE_HINT),
                JsonUtil.getString(json, KEY_TOKEN),
                JsonUtil.getStringMap(json, KEY_ADDITIONAL_PARAMETERS));
    }

    /**
     * Reads a token revocation request from a JSON string representation produced by
     * {@link #jsonSerializeString()}. This method is just a convenience wrapper for
     * {@link #jsonDeserialize(JSONObject)}, converting the JSON string to its JSON object form.
     * @throws JSONException if the provided JSON does not match the expected structure.
     */
    @NonNull
    public static RevokeTokenRequest jsonDeserialize(@NonNull String json) throws JSONException {
        checkNotNull(json, "json string cannot be null");
        return jsonDeserialize(new JSONObject(json));
    }
}
