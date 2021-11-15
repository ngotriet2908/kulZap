package org.zaproxy.addon.securityproxy.proxytests;

import org.apache.commons.httpclient.URI;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.securityproxy.ExtensionSecurityProxy;
import org.zaproxy.addon.securityproxy.SecurityProxyListener;
import org.zaproxy.addon.securityproxy.proxytests.constraints.AdjSwappedCharacterConstraint;
import org.zaproxy.addon.securityproxy.proxytests.constraints.ExtraCharacterConstraint;
import org.zaproxy.addon.securityproxy.proxytests.constraints.MissingCharacterConstraint;
import org.zaproxy.addon.securityproxy.proxytests.constraints.ReplacedCharacterConstraint;
import org.zaproxy.addon.securityproxy.proxytests.constraints.TypoSquattingConstraint;

import java.io.File;
import java.util.List;
import java.util.Scanner;

public class TypoSquattingTest extends ProxyTest{

    private final List<TypoSquattingConstraint> constraints;

    public static final String HOST_NAME_SAFE_RESULT = "safe";
    private static final String TYPO_HOST = "[TypoHost]";
    private static final String ORIGIN_HOST = "[OriginPage]";

    private static final Logger LOGGER = LogManager.getLogger(TypoSquattingTest.class);

    public TypoSquattingTest(ExtensionSecurityProxy proxy) {
        super(proxy);
        constraints = List.of(
                new AdjSwappedCharacterConstraint(),
                new ExtraCharacterConstraint(),
                new MissingCharacterConstraint(),
                new ReplacedCharacterConstraint()
        );
    }

    @Override
    public boolean isSafe(HttpMessage msg) {
        return isSafeWithReason(msg).equals(HOST_NAME_SAFE_RESULT);
    }


    public String isSafeWithReason(HttpMessage msg) {
        String testHostName = extractSearchHost(msg);

        String result1 = HOST_NAME_SAFE_RESULT;
        String result2 = HOST_NAME_SAFE_RESULT;

        for(String knownHostName : super.proxy.getKnownUrlList()) {
            if (knownHostName.equals(testHostName)) {
                return HOST_NAME_SAFE_RESULT;
            }

            for(TypoSquattingConstraint constraint : constraints) {
                if (constraint.passedConstraint(testHostName, knownHostName)) {
                    LOGGER.log(Level.INFO, "Constraint " +
                            constraint.getClass().getName() +
                            "Fail: " + testHostName + " - " + knownHostName);
                    result1 = knownHostName;
                    break;
                }
            }
        }

        if (msg.getRequestHeader().getHostName().equals(testHostName)) {
            return result1;
        }

        testHostName = msg.getRequestHeader().getHostName();
        for(String knownHostName : super.proxy.getKnownUrlList()) {
            if (knownHostName.equals(testHostName)) {
                return HOST_NAME_SAFE_RESULT;
            }

            for(TypoSquattingConstraint constraint : constraints) {
                if (constraint.passedConstraint(testHostName, knownHostName)) {
                    LOGGER.log(Level.INFO, "Constraint " +
                            constraint.getClass().getName() +
                            "Fail: " + testHostName + " - " + knownHostName);
                    result2 = knownHostName;
                    break;
                }
            }
        }

        if (result1.equals(HOST_NAME_SAFE_RESULT) || result2.equals(HOST_NAME_SAFE_RESULT)) {
            return HOST_NAME_SAFE_RESULT;
        }

        return result1;
    }


    public String uriStringToHostName(String uri) {
        try {
            return new URI(uri, true, "UTF-8").getHost();
        } catch (Exception e) {
            LOGGER.log(Level.ERROR, e.getMessage());
        }
        return null;
    }

    public String extractSearchHost(HttpMessage msg) {
        try {
            String ref = msg.getRequestHeader().getHeader("Referer");
            String origin = msg.getRequestHeader().getHeader("Origin");
            String testHostName;

            if (origin != null) {
                testHostName = new URI(origin, true, "UTF-8").getHost();
            } else if (ref != null) {
                testHostName = new URI(ref, true, "UTF-8").getHost();
            } else {
                testHostName = msg.getRequestHeader().getHostName();
            }

            return testHostName;
        } catch (Exception e) {
            LOGGER.log(Level.ERROR, e.getMessage());
        }

        return null;
    }

    @Override
    public String getTestName() {
        return "Typosquatting";
    }

    @Override
    public String getWarningPage(String... args) {
        String typoHost = args[0];
        String originPage = args[1];

        try {
            File ff = new File(Constant.getZapHome(), ExtensionSecurityProxy.HTML_TEMPLATE);
            Scanner myReader = new Scanner(ff);
            StringBuilder html_content = new StringBuilder();
            while (myReader.hasNextLine()) {
                html_content.append(myReader.nextLine()).append("\n");
            }
            myReader.close();

            return html_content.toString()
                    .replace(TYPO_HOST, typoHost)
                    .replace(ORIGIN_HOST, originPage);
        } catch (Exception e) {
            LOGGER.log(Level.ERROR, e.getMessage());
        }
        return null;
    }
}
