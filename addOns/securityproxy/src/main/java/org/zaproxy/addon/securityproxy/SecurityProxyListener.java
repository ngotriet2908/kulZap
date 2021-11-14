package org.zaproxy.addon.securityproxy;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.proxy.ProxyListener;
import org.parosproxy.paros.extension.history.ProxyListenerLog;
import org.parosproxy.paros.model.Model;
//import org.parosproxy.paros.network.*;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.brk.ExtensionBreak;

import java.io.File;
import java.util.Date;
import java.util.Locale;
import java.util.Scanner;

public class SecurityProxyListener implements ProxyListener {
    // Should be the last one before the listener that saves the HttpMessage to
    // the DB, this way the HttpMessage will be correctly shown to the user (to
    // edit it) because it could have been changed by other ProxyListener.
    public static final int PROXY_LISTENER_ORDER = ProxyListenerLog.PROXY_LISTENER_ORDER - 1;

    private static final String HTML_CONTENT_TYPE = "text/html";
    private static final String TYPO_LINK = "[TypoPage]";
    private static final String TYPO_HOST = "[TypoHost]";
    private static final String IS_SAFE_HEADER = "ZAP-IS-SAFE";
    private static final String ADD_TO_LEGIT_HOST = "/zapgroup8addtolegithost";

    private ExtensionSecurityProxy extension;
    private static final Logger LOGGER = LogManager.getLogger(SecurityProxyListener.class);



    public SecurityProxyListener(ExtensionSecurityProxy extension) {
        /*
         * This is how you can pass in your extension, which you may well need to use
         * when you actually do anything of use.
         */
        this.extension = extension;
    }

    @Override
    public boolean onHttpRequestSend(HttpMessage msg) {

        boolean isGood = isHostnameGood(msg);
        String contentType = msg.getRequestHeader().getHeader("Accept");
        contentType = (contentType == null) ? "null" : contentType;
        boolean containsHTML = contentType.contains(HTML_CONTENT_TYPE);

        logToOutput(
                "Request > isGood: " + isGood +
                ", host: " + msg.getRequestHeader().getHostName() +
                ", contains html: " + containsHTML +
                ", ref: " + ((msg.getRequestHeader().getHeader("Referer") != null)?
                                        msg.getRequestHeader().getHeader("Referer") : "null") +
                ", origin: " + ((msg.getRequestHeader().getHeader("Origin") != null)?
                msg.getRequestHeader().getHeader("Origin") : "null")
        );

        if (msg.getRequestHeader().getURI().toString().contains(ADD_TO_LEGIT_HOST)) {
            String legitHost = msg.getRequestHeader().getURI().toString()
                    .replace(ADD_TO_LEGIT_HOST.toLowerCase(Locale.ROOT), "")
                    .replace("https://", "");

            this.extension.getKnownUrlList().add(legitHost);
            logToOutput("Request > Saving Host: " + legitHost);

            try {
                msg.setResponseHeader(new HttpResponseHeader(
                        "HTTP/1.1 200 OK"
                                + HttpHeader.CRLF
                                + "Content-Type: text/html;charset=utf-8"
                                + HttpHeader.CRLF
                                + "Content-Language: en"));
                msg.setResponseBody(getWarningPageInString(msg));
                msg.getResponseHeader().setContentLength(msg.getResponseBody().length());
                msg.setTimeSentMillis(new Date().getTime());

                return true;
            } catch (HttpMalformedHeaderException e) {
                LOGGER.log(Level.ERROR, e.getMessage());
                logToOutput("Error: " + e.getMessage());
            }
            return false;
        }


        try {
            if (containsHTML) {
                if (isGood) return true;

                msg.setResponseHeader(new HttpResponseHeader(
                        "HTTP/1.1 200 OK"
                                + HttpHeader.CRLF
                                + "Content-Type: text/html;charset=utf-8"
                                + HttpHeader.CRLF
                                + "Content-Language: en"));

                msg.setResponseBody(getWarningPageInString(msg));
                msg.getResponseHeader().setContentLength(msg.getResponseBody().length());
                msg.setTimeSentMillis(new Date().getTime());

                return true;
            } else {
                return isGood;
            }
        } catch(Exception e) {
            LOGGER.log(Level.ERROR, e.getMessage());
        }

        return true;
    }



    @Override
    public boolean onHttpResponseReceive(HttpMessage msg) {
        return true;
    }

    public String getWarningPageInString(HttpMessage msg) {
        try {
            File ff = new File(Constant.getZapHome(), ExtensionSecurityProxy.HTML_TEMPLATE);
            Scanner myReader = new Scanner(ff);
            StringBuilder html_content = new StringBuilder();
            while (myReader.hasNextLine()) {
                html_content.append(myReader.nextLine()).append("\n");
            }
            myReader.close();

            return html_content.toString()
                    .replace(TYPO_LINK, msg.getRequestHeader().getURI().toString())
                    .replace(TYPO_HOST, msg.getRequestHeader().getHostName());
        } catch (Exception e) {
            LOGGER.log(Level.ERROR, e.getMessage());
        }
        return null;
    }

    @Override
    public int getArrangeableListenerOrder() {
        return PROXY_LISTENER_ORDER;
    }

    public void logToOutput(String msg) {
        if (View.isInitialised()) {
            // Running in daemon mode, shouldnt have been called
            View.getSingleton().getOutputPanel().append(msg + "\n");
            View.getSingleton().getOutputPanel().setTabFocus();
        }
    }

    public boolean isHostnameGood(HttpMessage msg) {
        String ref = msg.getRequestHeader().getHeader("Referer");
        String origin = msg.getRequestHeader().getHeader("Origin");

        boolean resRef = false;
        boolean resOrigin = false;
        boolean resHost;


        if (origin != null) {
            for(String knownUrl: this.extension.getKnownUrlList()) {
                if (origin.contains(knownUrl)) {
                    resOrigin = true;
                    break;
                }
            }
        }

        if (ref != null) {
            for(String knownUrl: this.extension.getKnownUrlList()) {
                if (ref.contains(knownUrl)) {
                    resRef = true;
                    break;
                }
            }
        }
        resHost = this.extension.getKnownUrlList().contains(msg.getRequestHeader().getHostName());
        return resRef | resHost | resOrigin;
    }

    public boolean isGood(HttpMessage msg) {
        String hostName = msg.getRequestHeader().getHostName();
        return this.extension.getKnownUrlList().contains(hostName);
    }
}
