package org.zaproxy.addon.securityproxy;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.core.proxy.ProxyListener;
import org.parosproxy.paros.extension.history.ProxyListenerLog;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.securityproxy.proxytests.TypoSquattingTest;
import org.zaproxy.addon.securityproxy.proxytests.Website;

import java.util.Date;
import java.util.Locale;

/**
 * A custom proxy listener that process the requests from user and apply
 * security constraint such as TypoSquatting Prevention
 */
public class SecurityProxyListener implements ProxyListener {
    // Should be the last one before the listener that saves the HttpMessage to
    // the DB, this way the HttpMessage will be correctly shown to the user (to
    // edit it) because it could have been changed by other ProxyListener.
    public static final int PROXY_LISTENER_ORDER = ProxyListenerLog.PROXY_LISTENER_ORDER - 1;

    private static final String HTML_CONTENT_TYPE = "text/html";
    private static final String TYPO_LINK = "[TypoPage]";
    private static final String TYPO_HOST = "[TypoHost]";
    private static final String REDIRECT_HOST = "[RedirectHost]";
    private static final String IS_SAFE_HEADER = "ZAP-IS-SAFE";
    private static final String ADD_TO_LEGIT_HOST = "/zapgroup8addtolegithost";
    private static final String ADD_REDIRECT_HOST = "/zapgroup8addredirect";

    private ExtensionSecurityProxy extension;
    private static final Logger LOGGER = LogManager.getLogger(SecurityProxyListener.class);

    private TypoSquattingTest typoSquattingTest;

    public SecurityProxyListener(ExtensionSecurityProxy extension) {
        this.extension = extension;
        this.typoSquattingTest = new TypoSquattingTest(this);
    }

    /**
     * When a request is received, the method determine the following:
     * - If the hostname is in the saved Typo list (if yes, then extract the redirect host then redirect the user)
     * - If the user indicates in the request that they want to save a typo host as legitimate host -> then save the host to known Host list
     * - If the user indicates in the request that they want to save a typo host with the intended host as preference
     *      then save the preference and redirect the user in future requests
     * - If the page contains HTML  (usually when the user enter a link in the address bar)
     * -- if no violations found then allow the user to access the page
     * -- show the user a warning page telling them that they violate the Typo Squatting test
     * - For other requests, allow if the hostname pass the Tests
     * @param msg user requests
     * @return the unmodified request if the hostname is safe and modified in case of violated request
     */
    @Override
    public boolean onHttpRequestSend(HttpMessage msg) {

        try {
            boolean isGood = this.typoSquattingTest.isSafe(msg);

//            Check if the hostname is in the saved Typo list (if yes, then extract the redirect host then redirect the user)
            if (!isGood) {
                for (Website web : this.typoSquattingTest.getTypoWebsites()) {
                    if (web.getHost().equals(msg.getRequestHeader().getHostName())) {
                        msg.setResponseHeader(new HttpResponseHeader(
                                "HTTP/1.1 200 OK"
                                        + HttpHeader.CRLF
                                        + "Content-Type: text/html;charset=utf-8"
                                        + HttpHeader.CRLF
                                        + "Content-Language: en"));
                        String html = this.getTypoSquattingTest().getRedirectPage();
                        msg.setResponseBody(html.replace(REDIRECT_HOST, "https://" + web.getDirectedWebsite().getHost()));
                        msg.getResponseHeader().setContentLength(msg.getResponseBody().length());
                        msg.setTimeSentMillis(new Date().getTime());

                        return true;
                    }
                }

            }

            String isGoodHostName = this.typoSquattingTest.extractSearchHost(msg);
            String contentType = msg.getRequestHeader().getHeader("Accept");
            contentType = (contentType == null) ? "null" : contentType;
            boolean containsHTML = contentType.contains(HTML_CONTENT_TYPE);

            logToOutput(
                    "Request > isGood: " + isGood +
                            ", host: " + msg.getRequestHeader().getHostName() +
                            ", contains html: " + containsHTML +
                            ", ref: " + ((msg.getRequestHeader().getHeader("Referer") != null) ?
                            this.typoSquattingTest.uriStringToHostName(msg.getRequestHeader().getHeader("Referer")) : "null") +
                            ", origin: " + ((msg.getRequestHeader().getHeader("Origin") != null) ?
                            this.typoSquattingTest.uriStringToHostName(msg.getRequestHeader().getHeader("Origin")) : "null")
            );


            //  If request contains pre-made keywords ADD_TO_LEGIT_HOST (add the host to legit host) -> then save the host to known Host list
            if (msg.getRequestHeader().getURI().toString().contains(ADD_TO_LEGIT_HOST)) {
                String legitHost = msg.getRequestHeader().getURI().toString()
                        .replace(ADD_TO_LEGIT_HOST.toLowerCase(Locale.ROOT), "")
                        .replace("https://", "");

                if (this.typoSquattingTest.addKnownHost(legitHost)) {
                    logToOutput("Operation > Add new KnownHost 1: " + legitHost);
                }

                msg.setResponseHeader(new HttpResponseHeader(
                        "HTTP/1.1 200 OK"
                                + HttpHeader.CRLF
                                + "Content-Type: text/html;charset=utf-8"
                                + HttpHeader.CRLF
                                + "Content-Language: en"));
                msg.setResponseBody(this.typoSquattingTest.getWarningPage("a", "a"));
                msg.getResponseHeader().setContentLength(msg.getResponseBody().length());
                msg.setTimeSentMillis(new Date().getTime());

                return true;
            }

            //  If request contains pre-made keywords ADD_REDIRECT_HOST (add typo host with redirect host preference) -> then save the preference
            if (msg.getRequestHeader().getURI().toString().contains(ADD_REDIRECT_HOST)) {
                String params = msg.getRequestHeader().getURI().toString()
                        .replace(ADD_REDIRECT_HOST.toLowerCase(Locale.ROOT), "")
                        .replace("https://", "");

                String typoHost = params.split(";")[0];
                String originHost = params.split(";")[1];

                this.typoSquattingTest.addTypoHost(typoHost, this.typoSquattingTest.getKnownWebsite(originHost));
                logToOutput("Operation > Add Typo Redirect: " + typoHost + " -> " + originHost);

                msg.setResponseHeader(new HttpResponseHeader(
                        "HTTP/1.1 200 OK"
                                + HttpHeader.CRLF
                                + "Content-Type: text/html;charset=utf-8"
                                + HttpHeader.CRLF
                                + "Content-Language: en"));
                msg.setResponseBody(this.typoSquattingTest.getWarningPage("a", "a"));
                msg.getResponseHeader().setContentLength(msg.getResponseBody().length());
                msg.setTimeSentMillis(new Date().getTime());

                return true;
            }

            // If the page contains HTML -> usually when the user enter a link in the address bar
            if (containsHTML) {

                // If the hostname is good and not a typo -> add the host to knownHost list
                if (isGood && !this.typoSquattingTest.isTypoWebsite(isGoodHostName)) {
                    if (this.typoSquattingTest.addKnownHost(isGoodHostName)) {
                        logToOutput("Operation > Add new KnownHost 2: " + isGoodHostName);
                    }
                    return true;
                } else if (isGood) {
                    return true;
                }


                // Otherwise, the host failed the typo test -> send the warning page
                String originalHost = this.typoSquattingTest.isSafeWithReason(msg);

                msg.setResponseHeader(new HttpResponseHeader(
                        "HTTP/1.1 200 OK"
                                + HttpHeader.CRLF
                                + "Content-Type: text/html;charset=utf-8"
                                + HttpHeader.CRLF
                                + "Content-Language: en"));

                msg.setResponseBody(this.typoSquattingTest.getWarningPage(
                        msg.getRequestHeader().getHostName(),
                        originalHost)
                );

                msg.getResponseHeader().setContentLength(msg.getResponseBody().length());
                msg.setTimeSentMillis(new Date().getTime());

                return true;
            } else {
                return isGood;
            }
        } catch (Exception e) {
            LOGGER.log(Level.ERROR, e.getMessage());
        }
        return true;
    }

    /**
     * Allow all response to be forwarded to the user
     * @param msg user request
     * @return always allow
     */
    @Override
    public boolean onHttpResponseReceive(HttpMessage msg) {
        return true;
    }

    @Override
    public int getArrangeableListenerOrder() {
        return PROXY_LISTENER_ORDER;
    }

    /**
     * Log to output in ZAP application
     * @param msg user request
     */
    public void logToOutput(String msg) {
        if (View.isInitialised()) {
            // Running in daemon mode, shouldnt have been called
            View.getSingleton().getOutputPanel().append(msg + "\n");
            View.getSingleton().getOutputPanel().setTabFocus();
        }
    }

    /**
     * @return return the ZAP extension for usage
     */
    public ExtensionSecurityProxy getExtension() {
        return extension;
    }

    public TypoSquattingTest getTypoSquattingTest() {
        return typoSquattingTest;
    }
}
