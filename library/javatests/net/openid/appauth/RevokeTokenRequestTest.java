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

import static net.openid.appauth.TestValues.TEST_CLIENT_ID;
import static net.openid.appauth.TestValues.TEST_ID_TOKEN;
import static net.openid.appauth.TestValues.getTestServiceConfig;
import static org.assertj.core.api.Assertions.assertThat;

import org.json.JSONException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.util.HashMap;
import java.util.Map;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 16)
public class RevokeTokenRequestTest {

    private static final Map<String, String> TEST_ADDITIONAL_PARAMS;

    static {
        TEST_ADDITIONAL_PARAMS = new HashMap<>();
        TEST_ADDITIONAL_PARAMS.put("test_key1", "test_value1");
        TEST_ADDITIONAL_PARAMS.put("test_key2", "test_value2");
    }

    private RevokeTokenRequest.Builder mRequestBuilder;

    @Before
    public void setUp() throws JSONException {
        mRequestBuilder = new RevokeTokenRequest.Builder(
                getTestServiceConfig(),
                TEST_CLIENT_ID,
                TEST_ID_TOKEN);
    }

    /* ********************************** Builder() ***********************************************/

    @Test(expected = NullPointerException.class)
    @SuppressWarnings("ConstantConditions")
    public void testBuild_nullConfiguration() {
        new RevokeTokenRequest.Builder(null, TEST_CLIENT_ID, TEST_ID_TOKEN).build();
    }

    @Test(expected = NullPointerException.class)
    @SuppressWarnings("ConstantConditions")
    public void testBuild_nullClientId() {
        new RevokeTokenRequest.Builder(getTestServiceConfig(), null, TEST_ID_TOKEN);
    }

    @Test(expected = NullPointerException.class)
    @SuppressWarnings("ConstantConditions")
    public void testBuild_nullToken() {
        new RevokeTokenRequest.Builder(getTestServiceConfig(), TEST_CLIENT_ID, null);
    }

    /* ********************************** tokenTypeHint *******************************************/

    @Test
    public void testBuilder_setTokenTypeHint() {
        String tokenTypeHint = RevokeTokenRequest.TOKEN_TYPE_ACCESS;
        mRequestBuilder.setTokenTypeHint(tokenTypeHint);
        RevokeTokenRequest request = mRequestBuilder.build();
        assertThat(request.tokenTypeHint).isEqualTo(tokenTypeHint);
    }

    /* ******************************* additionalParams *******************************************/

    @Test(expected = IllegalArgumentException.class)
    public void testBuilder_setAdditionalParams_withBuiltInParam() {
        Map<String, String> additionalParams = new HashMap<>();
        additionalParams.put(RevokeTokenRequest.PARAM_TOKEN_TYPE_HINT,
                RevokeTokenRequest.TOKEN_TYPE_ACCESS);
        mRequestBuilder.setAdditionalParameters(additionalParams);
    }

    /* ******************************* getRequestParameters() *************************************/

    @Test
    public void testGetRequestParameters_forToken() {
        RevokeTokenRequest request = mRequestBuilder.build();
        Map<String, String> params = request.getRequestParameters();
        assertThat(params).containsEntry(
                RevokeTokenRequest.PARAM_TOKEN,
                TEST_ID_TOKEN);
    }

    @Test
    public void testGetRequestParameters_forTokenTypeHint() {
        String tokenTypeHint = RevokeTokenRequest.TOKEN_TYPE_ACCESS;
        RevokeTokenRequest request = mRequestBuilder
                .setTokenTypeHint(tokenTypeHint)
                .build();
        Map<String, String> params = request.getRequestParameters();
        assertThat(params).containsEntry(
                RevokeTokenRequest.PARAM_TOKEN_TYPE_HINT,
                tokenTypeHint);
    }

    @Test
    public void testGetRequestParameters_forAdditionalParameters() {
        RevokeTokenRequest request = mRequestBuilder
                .setAdditionalParameters(TEST_ADDITIONAL_PARAMS)
                .build();
        Map<String, String> params = request.getRequestParameters();
        assertThat(params).containsEntry("test_key1", "test_value1");
        assertThat(params).containsEntry("test_key2", "test_value2");
    }

    /* ************************** jsonSerialize() / jsonDeserialize() *****************************/

    @Test
    public void testJsonSerialize_clientId() throws Exception {
        RevokeTokenRequest copy = serializeDeserialize(
                mRequestBuilder.setClientId(TEST_CLIENT_ID).build());
        assertThat(copy.clientId).isEqualTo(TEST_CLIENT_ID);
    }

    @Test
    public void testJsonSerialize_token() throws Exception {
        RevokeTokenRequest copy = serializeDeserialize(
                mRequestBuilder.setClientId(TEST_ID_TOKEN).build());
        assertThat(copy.token).isEqualTo(TEST_ID_TOKEN);
    }

    @Test
    public void testJsonSerialize_tokenTypeHint() throws Exception {
        String tokenTypeHint = RevokeTokenRequest.TOKEN_TYPE_ACCESS;
        RevokeTokenRequest copy = serializeDeserialize(
                mRequestBuilder.setTokenTypeHint(tokenTypeHint).build());
        assertThat(copy.tokenTypeHint).isEqualTo(tokenTypeHint);
    }

    @Test
    public void testJsonSerialize_additionalParams() throws JSONException {
        RevokeTokenRequest copy = serializeDeserialize(
                mRequestBuilder.setAdditionalParameters(TEST_ADDITIONAL_PARAMS).build());
        assertThat(copy.additionalParameters).isEqualTo(TEST_ADDITIONAL_PARAMS);
    }

    private RevokeTokenRequest serializeDeserialize(RevokeTokenRequest request)
            throws JSONException {
        return RevokeTokenRequest.jsonDeserialize(request.jsonSerializeString());
    }
}
