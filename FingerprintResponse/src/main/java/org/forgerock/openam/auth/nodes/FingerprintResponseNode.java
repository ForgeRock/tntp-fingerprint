/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2023 ForgeRock AS.
 */
/**
 * jon.knight@forgerock.com
 *
 * A node that requests response from Fingerprint.com based on requestId
 */


package org.forgerock.openam.auth.nodes;

import com.google.inject.assistedinject.Assisted;
import com.iplanet.sso.SSOException;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.util.i18n.PreferredLocales;
import org.forgerock.openam.utils.JsonValueBuilder;

import javax.inject.Inject;

import java.util.Set;
import java.util.List;
import java.util.Optional;
import java.util.ResourceBundle;
import java.util.Map;
import java.util.HashMap;
import com.google.common.collect.ImmutableList;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;




@Node.Metadata(outcomeProvider = FingerprintResponseNode.OutcomeProvider.class,
        configClass = FingerprintResponseNode.Config.class)
public class FingerprintResponseNode extends AbstractDecisionNode {

    private final Logger logger = LoggerFactory.getLogger(FingerprintResponseNode.class);
    private String loggerPrefix = "[FingerprintResponseNode]" + FingerprintResponseNodePlugin.logAppender;

    private final Config config;
    private static final String BUNDLE = FingerprintResponseNode.class.getName();


    /**
     * Configuration for the node.
     */

    
    public interface Config {
       @Attribute(order = 100)
        default String apiKey() { return "apiKey"; }

        @Attribute(order = 200)
        default String url() { return "https://eu.api.fpjs.io/events/"; }

        @Attribute(order = 300)
        default String visitorID() { return "deviceFingerPrint"; }

        @Attribute(order = 400)
        default boolean fullResponse() { return false; }

        @Attribute(order = 500)
        default String response() { return "payload"; }
    }



    private final CoreWrapper coreWrapper;

    /**
     * Guice constructor.
     * @param config The node configuration.
     * @throws NodeProcessException If there is an error reading the configuration.
     */
    @Inject
    public FingerprintResponseNode(@Assisted Config config, CoreWrapper coreWrapper) throws NodeProcessException {
        this.config = config;
        this.coreWrapper = coreWrapper;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {

        try {
            logger.debug(loggerPrefix + "Started");

            String requestId = context.sharedState.get("deviceRequestId").asString();

            URL url = new URL(config.url() + requestId + "?api_key=" + config.apiKey());
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "application/json");
            conn.setRequestProperty("content-type", "application/json");
            if (conn.getResponseCode() != 200) {
                logger.debug(loggerPrefix + "HTTP failed, response code:" + conn.getResponseCode());
                throw new RuntimeException(loggerPrefix + "HTTP error code : " + conn.getResponseCode());
            }

            BufferedReader br = new BufferedReader(new InputStreamReader((conn.getInputStream())));
            String output;
            String json = "";

            while ((output = br.readLine()) != null) {
                json = json + output;
            }
            conn.disconnect();
            
            JsonValue resultJson = JsonValueBuilder.toJsonValue(json);
            String visitorID = resultJson.get("products").get("identification").get("data").get("visitorId").asString();
            Double score = resultJson.get("products").get("identification").get("data").get("confidence").get("score").asDouble();

            JsonValue newSharedState = context.sharedState.copy();
            newSharedState.put(config.visitorID(), visitorID);
            newSharedState.put("deviceConfidenceScore", score);

            if (config.fullResponse()) newSharedState.put(config.response(), json);
            return goTo(true).replaceSharedState(newSharedState).build();

        } catch (Exception ex) {
            String stackTrace = org.apache.commons.lang.exception.ExceptionUtils.getStackTrace(ex);
            logger.error(loggerPrefix + "Exception occurred: " + stackTrace);
            context.getStateFor(this).putShared(loggerPrefix + "Exception", ex.getMessage());
            context.getStateFor(this).putShared(loggerPrefix + "StackTrace", stackTrace);
            return Action.goTo("error").build();
        } 
    }


    public static class OutcomeProvider implements StaticOutcomeProvider {
        @Override
        public List<Outcome> getOutcomes(PreferredLocales locales) {
            ResourceBundle bundle = locales.getBundleInPreferredLocale(FingerprintResponseNode.BUNDLE,
                    OutcomeProvider.class.getClassLoader());

            return ImmutableList.of(
                new Outcome("true", "true"),
                new Outcome("error", "error")
            );
        }
    }
}
