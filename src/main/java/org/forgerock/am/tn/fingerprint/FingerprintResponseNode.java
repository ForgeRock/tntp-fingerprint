/*
 * This code is to be used exclusively in connection with ForgeRock’s software or services. 
 * ForgeRock only offers ForgeRock software or services to legal entities who have entered 
 * into a binding license agreement with ForgeRock.  
 */

package org.forgerock.am.tn.fingerprint;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Date;
import java.util.List;
import java.util.ResourceBundle;

import javax.inject.Inject;

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

import com.google.common.collect.ImmutableList;
import com.google.inject.assistedinject.Assisted;



@Node.Metadata(outcomeProvider = FingerprintResponseNode.OutcomeProvider.class,
        configClass = FingerprintResponseNode.Config.class, tags = {"marketplace", "trustnetwork" })
public class FingerprintResponseNode extends AbstractDecisionNode {

    private final Logger logger = LoggerFactory.getLogger(FingerprintResponseNode.class);
    private String loggerPrefix = "[FingerprintResponseNode]" + FingerprintProfilerNodePlugin.logAppender;

    private final Config config;
    private static final String BUNDLE = FingerprintResponseNode.class.getName();
	private static final String SUCCESS = "SUCCESS";
	private static final String ERROR = "ERROR";


    /**
     * Configuration for the node.
     */

    
    public interface Config {
        @Attribute(order = 100)
        @Password
        char[] apiKey();

        @Attribute(order = 200)
        default String url() { return "https://eu.api.fpjs.io/events/"; }

        @Attribute(order = 300)
        default String visitorID() { return "deviceFingerPrint"; }

        @Attribute(order = 400)
        default boolean fullResponse() { return false; }

        @Attribute(order = 500)
        default String response() { return "payload"; }
    }


    /**
     * Guice constructor.
     * @param config The node configuration.
     * @throws NodeProcessException If there is an error reading the configuration.
     */
    @Inject
    public FingerprintResponseNode(@Assisted Config config) throws NodeProcessException {
        this.config = config;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {

    	
    	HttpURLConnection conn = null;
    	BufferedReader br = null;
        try {
            logger.debug(loggerPrefix + "Started");
            NodeState ns = context.getStateFor(this);

            String requestId = ns.get("deviceRequestId").asString();

            URL url = new URL(config.url() + requestId + "?api_key=" + (new String(config.apiKey())));
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "application/json");
            conn.setRequestProperty("content-type", "application/json");
            if (conn.getResponseCode() != 200) {
                logger.debug(loggerPrefix + "HTTP failed, response code:" + conn.getResponseCode());
                throw new RuntimeException(loggerPrefix + "HTTP error code : " + conn.getResponseCode());
            }

            br = new BufferedReader(new InputStreamReader((conn.getInputStream())));
            String output;
            String json = "";

            while ((output = br.readLine()) != null) {
                json = json + output;
            }
            
            JsonValue resultJson = JsonValueBuilder.toJsonValue(json);
            String visitorID = resultJson.get("products").get("identification").get("data").get("visitorId").asString();
            Double score = resultJson.get("products").get("identification").get("data").get("confidence").get("score").asDouble();
        
            ns.putShared(config.visitorID(), visitorID);
            ns.putShared("deviceConfidenceScore", score);

            if (config.fullResponse()) 
            	ns.putShared(config.response(), json);
            return Action.goTo(SUCCESS).build();

        } catch (Exception ex) {
			String stackTrace = org.apache.commons.lang.exception.ExceptionUtils.getStackTrace(ex);
			logger.error(loggerPrefix + "Exception occurred: " + stackTrace);
			context.getStateFor(this).putTransient(loggerPrefix + "Exception", new Date() + ": " + ex.getMessage());
			context.getStateFor(this).putTransient(loggerPrefix + "StackTrace", new Date() + ": " + stackTrace);
			return Action.goTo(ERROR).withHeader("Error occurred").withErrorMessage(ex.getMessage()).build();
        } 
        finally {
        	if (conn!=null)
        		try {
        			conn.disconnect();
        		}
        		catch(Exception e) {
        			//Do nothing... just attempting to close the connection
        		}
        	
        	if (br!=null)
        		try {
        			br.close();
        		}
        		catch(Exception e) {
            		//Do nothing... just attempting to close the connection
        		}
        }
    }


    public static class OutcomeProvider implements StaticOutcomeProvider {
        @Override
        public List<Outcome> getOutcomes(PreferredLocales locales) {
            ResourceBundle bundle = locales.getBundleInPreferredLocale(FingerprintResponseNode.BUNDLE,
                    OutcomeProvider.class.getClassLoader());

            return ImmutableList.of(
                new Outcome(SUCCESS, bundle.getString("successOutcome")),
                new Outcome(ERROR, bundle.getString("errorOutcome"))
            );
        }
    }
}
