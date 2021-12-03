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

import static net.openid.appauth.Preconditions.checkNotEmpty;
import static net.openid.appauth.Preconditions.checkNotNull;

import androidx.annotation.NonNull;
import androidx.annotation.VisibleForTesting;

import org.json.JSONException;
import org.json.JSONObject;

/**
 * A response to a token revocation request.
 *
 * @see RevokeTokenRequest
 * @see "OAuth 2.0 Token Revocation (RFC 7009), Section 2.2
 * <https://datatracker.ietf.org/doc/html/rfc7009#section-2.2>"
 */
public class RevokeTokenResponse {

    @VisibleForTesting
    static final String KEY_REQUEST = "request";

    /**
     * The token revocation request associated with this response.
     */
    @NonNull
    public final RevokeTokenRequest request;

    /**
     * Creates instances of {@link TokenResponse}.
     */
    public static final class Builder {
        @NonNull
        private RevokeTokenRequest mRequest;

        /**
         * Creates a token response associated with the specified request.
         */
        public Builder(@NonNull RevokeTokenRequest request) {
            setRequest(request);
        }

        /**
         * Specifies the request associated with this response. Must not be null.
         */
        @NonNull
        public Builder setRequest(@NonNull RevokeTokenRequest request) {
            mRequest = checkNotNull(request, "request cannot be null");
            return this;
        }

        /**
         * Creates the token revocation response instance.
         */
        public RevokeTokenResponse build() {
            return new RevokeTokenResponse(mRequest);
        }
    }

    RevokeTokenResponse(
            @NonNull RevokeTokenRequest request) {
        this.request = request;
    }

    /**
     * Produces a JSON string representation of the token revocation response for persistent storage
     * or local transmission (e.g. between activities).
     */
    public JSONObject jsonSerialize() {
        JSONObject json = new JSONObject();
        JsonUtil.put(json, KEY_REQUEST, request.jsonSerialize());
        return json;
    }

    /**
     * Produces a JSON string representation of the token revocation response for persistent storage
     * or local transmission (e.g. between activities). This method is just a convenience wrapper
     * for {@link #jsonSerialize()}, converting the JSON object to its string form.
     */
    public String jsonSerializeString() {
        return jsonSerialize().toString();
    }

    /**
     * Reads a token revocation response from a JSON string, and associates it with the provided
     * request. If a request is not provided, its serialized form is expected to be found in the
     * JSON (as if produced by a prior call to {@link #jsonSerialize()}.
     * @throws JSONException if the JSON is malformed or missing required fields.
     */
    @NonNull
    public static RevokeTokenResponse jsonDeserialize(@NonNull JSONObject json)
            throws JSONException {
        if (!json.has(KEY_REQUEST)) {
            throw new IllegalArgumentException(
                    "token revocation request not provided and not found in JSON");
        }
        return new RevokeTokenResponse(
                RevokeTokenRequest.jsonDeserialize(json.getJSONObject(KEY_REQUEST)));
    }

    /**
     * Reads a token revocation response from a JSON string, and associates it with the provided
     * request. If a request is not provided, its serialized form is expected to be found in the
     * JSON (as if produced by a prior call to {@link #jsonSerialize()}.
     * @throws JSONException if the JSON is malformed or missing required fields.
     */
    @NonNull
    public static RevokeTokenResponse jsonDeserialize(@NonNull String jsonStr)
            throws JSONException {
        checkNotEmpty(jsonStr, "jsonStr cannot be null or empty");
        return jsonDeserialize(new JSONObject(jsonStr));
    }
}
