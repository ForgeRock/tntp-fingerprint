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
 * marcin.zimny@forgerock.com
 * An authentication node which uses Javascript library for device fingerprinting
 */


package org.forgerock.openam.auth.nodes;

import com.google.inject.assistedinject.Assisted;
import com.sun.identity.authentication.callbacks.HiddenValueCallback;
import com.sun.identity.authentication.callbacks.ScriptTextOutputCallback;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.google.common.base.Strings;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
import javax.security.auth.callback.Callback;
import java.util.Optional;
import static org.forgerock.openam.auth.node.api.Action.send;
import org.forgerock.openam.utils.JsonValueBuilder;
import org.forgerock.util.i18n.PreferredLocales;

import java.util.Set;
import java.util.List;
import java.util.Optional;
import java.util.ResourceBundle;
import java.util.Map;
import java.util.HashMap;
import com.google.common.collect.ImmutableList;

import javax.inject.Inject;
import org.forgerock.openam.sm.annotations.adapters.Password;


/**
 * A node that executes a client-side Javascript and stores any resulting output in the shared state.
 */

@Node.Metadata(outcomeProvider = FingerprintProfilerNode.OutcomeProvider.class,
        configClass = FingerprintProfilerNode.Config.class)
public class FingerprintProfilerNode extends AbstractDecisionNode {


    private final Logger logger = LoggerFactory.getLogger(FingerprintProfilerNode.class);
    private String loggerPrefix = "[FingerprintProfilerNode]" + FingerprintProfilerNodePlugin.logAppender;

    private final Config config;
    private static final String BUNDLE = FingerprintProfilerNode.class.getName();


    /**
     * Configuration for the node.
     */


    public enum Region { GLOBAL, EU, ASIA }
    public String getRegion(Region region) {
        if (region == Region.EU) return "eu";
        else if (region == Region.ASIA) return "ap";
        else return "us";
    }

    public interface Config {
        @Attribute(order = 100)
        @Password
        char[] apiKey();

        @Attribute(order = 200)
        default String url() { return ""; }

        @Attribute(order = 300)
        default String apiEndpointURL() { return ""; }

        @Attribute(order = 400)
        default Region region() {
            return Region.GLOBAL;
        }

        @Attribute(order = 500)
        default String visitorID() { return "deviceFingerPrint"; }

        @Attribute(order = 600)
        default boolean ztm() { return false; }
    }


    /**
     * Guice constructor.
     * @param config The node configuration.
     * @throws NodeProcessException If there is an error reading the configuration.
     */
    @Inject
    public FingerprintProfilerNode(@Assisted Config config) throws NodeProcessException {
        this.config = config;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {

        try {

            logger.debug(loggerPrefix + "Started");

            Optional<String> result = context.getCallback(HiddenValueCallback.class).map(HiddenValueCallback::getValue).filter(scriptOutput -> !Strings.isNullOrEmpty(scriptOutput));

            if (result.isPresent()) {
                JsonValue newSharedState = context.sharedState.copy();

                JsonValue resultJson = JsonValueBuilder.toJsonValue(result.get());
                if (!config.ztm()) {
                    newSharedState.put(config.visitorID(), resultJson.get("visitorID"));
                    newSharedState.put("deviceConfidenceScore", resultJson.get("score"));
                }
                newSharedState.put("deviceRequestId", resultJson.get("requestID"));

                return goTo(true).replaceSharedState(newSharedState).build();
            } else {
              String fpUrl = config.url();
              if(fpUrl == null || fpUrl == "") {
                fpUrl = "https://fpjscdn.net/v3";
              }
              String clientSideScriptExecutorFunction = createClientSideScript(fpUrl, new String(config.apiKey()), config.apiEndpointURL(), getRegion(config.region()));
              ScriptTextOutputCallback scriptAndSelfSubmitCallback =
                      new ScriptTextOutputCallback(clientSideScriptExecutorFunction);

              HiddenValueCallback hiddenValueCallback = new HiddenValueCallback("clientScriptOutputData");

              Callback[] callbacks = new Callback[]{scriptAndSelfSubmitCallback, hiddenValueCallback};

              return send(callbacks).build();
            }
        } catch (Exception ex) {
            String stackTrace = org.apache.commons.lang.exception.ExceptionUtils.getStackTrace(ex);
            logger.error(loggerPrefix + "Exception occurred: " + stackTrace);
            context.getStateFor(this).putShared(loggerPrefix + "Exception", ex.getMessage());
            context.getStateFor(this).putShared(loggerPrefix + "StackTrace", stackTrace);
            return Action.goTo("error").build();
        }

    }

    public static String createClientSideScript(String url, String apiKey, String apiEndpointURL, String region) {
        String sRegion = ((apiEndpointURL != "" && apiEndpointURL != null) ? "" : " region: \"" + region + "\" \n");
        String sEndpoint = ((apiEndpointURL != "" && apiEndpointURL != null) ? " endpoint: \"" + apiEndpointURL + "?region=" + region + "\" \n" : "");
        String sImport = ((url == "https://fpjscdn.net/v3") ? "const fpPromise = import('" + url + "/" + apiKey + "') \n" : "const fpPromise = import('" + url + "?apiKey=" + apiKey + "') \n");

        return sImport + ".then(FingerprintJS => FingerprintJS.load({ \n" + sRegion + sEndpoint +
                      "})) \n" +
                      "fpPromise \n" +
                      ".then(fp => fp.get()) \n" +
                      ".then(result => { \n" +
                      "  var visitorId = (result.visitorId)  \n" +
                      "  var requestId = (result.requestId) \n" +
                      "  var confidence = JSON.stringify(result.confidence) \n" +
                      "  var output = JSON.parse(confidence) \n" +
                      "  output[\"requestID\"] = requestId \n " +
                      "  output[\"visitorID\"] = visitorId \n " +
                      "  console.log(output) \n" +
                      "  document.getElementById('clientScriptOutputData').value=JSON.stringify(output)   \n" +
                      "  document.getElementById('loginButton_0').click() }) \n" +
                      ".catch(err => { console.log(err); document.getElementById('loginButton_0').click(); }) ";
    }


    public static class OutcomeProvider implements StaticOutcomeProvider {
        @Override
        public List<Outcome> getOutcomes(PreferredLocales locales) {
            ResourceBundle bundle = locales.getBundleInPreferredLocale(FingerprintProfilerNode.BUNDLE,
                    OutcomeProvider.class.getClassLoader());

            return ImmutableList.of(
                new Outcome("true", "true"),
                new Outcome("error", "error")
            );
        }
    }
}
