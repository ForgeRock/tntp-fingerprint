/*
 * This code is to be used exclusively in connection with ForgeRock’s software or services. 
 * ForgeRock only offers ForgeRock software or services to legal entities who have entered 
 * into a binding license agreement with ForgeRock.  
 */

package org.forgerock.am.tn.fingerprint;

import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.ResourceBundle;

import javax.inject.Inject;
import javax.security.auth.callback.Callback;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.NodeState;
import org.forgerock.openam.auth.node.api.StaticOutcomeProvider;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.sm.annotations.adapters.Password;
import org.forgerock.openam.utils.JsonValueBuilder;
import org.forgerock.util.i18n.PreferredLocales;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import com.google.inject.assistedinject.Assisted;
import com.sun.identity.authentication.callbacks.HiddenValueCallback;
import com.sun.identity.authentication.callbacks.ScriptTextOutputCallback;


/**
 * A node that executes a client-side Javascript and stores any resulting output in the shared state.
 */

@Node.Metadata(outcomeProvider = FingerprintProfilerNode.OutcomeProvider.class,
        configClass = FingerprintProfilerNode.Config.class, tags = {"marketplace", "trustnetwork" })
public class FingerprintProfilerNode extends AbstractDecisionNode {


    private final Logger logger = LoggerFactory.getLogger(FingerprintProfilerNode.class);
    private String loggerPrefix = "[FingerprintProfilerNode]" + FingerprintProfilerNodePlugin.logAppender;

    private final Config config;
    private static final String BUNDLE = FingerprintProfilerNode.class.getName();
	private static final String NEXT = "NEXT";
	private static final String ERROR = "ERROR";


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
            	NodeState ns = context.getStateFor(this);
                

                JsonValue resultJson = JsonValueBuilder.toJsonValue(result.get());
                if (!config.ztm()) {
                	ns.putShared(config.visitorID(), resultJson.get("visitorID"));
                	ns.putShared("deviceConfidenceScore", resultJson.get("score"));
                }
                ns.putShared("deviceRequestId", resultJson.get("requestID"));

                return Action.goTo(NEXT).build();
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

              return Action.send(callbacks).build();
            }
        } catch (Exception ex) {
			String stackTrace = org.apache.commons.lang.exception.ExceptionUtils.getStackTrace(ex);
			logger.error(loggerPrefix + "Exception occurred: " + stackTrace);
			context.getStateFor(this).putTransient(loggerPrefix + "Exception", new Date() + ": " + ex.getMessage());
			context.getStateFor(this).putTransient(loggerPrefix + "StackTrace", new Date() + ": " + stackTrace);
			return Action.goTo(ERROR).withHeader("Error occurred").withErrorMessage(ex.getMessage()).build();
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
                new Outcome(NEXT, bundle.getString("nextOutcome")),
                new Outcome(ERROR, bundle.getString("errorOutcome"))
            );
        }
    }
}
