package org.zaproxy.addon.securityproxy.proxytests;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.securityproxy.ExtensionSecurityProxy;
import org.zaproxy.addon.securityproxy.SecurityProxyListener;
import org.mockito.Mockito;

import java.util.List;

public class SecurityProxyListenerTests {
    private TypoSquattingTest test;
    private SecurityProxyListener listener;

    private static final String HTTPS = "https://";

    /**
     * Initialize the google and youtube as visited legitimate.
     * Initialize one preference from user to auto-redirect from
     * typo hostname youtbe to youtube.
     * hostname. Also initialize TypoSquattingTest.
     */
    @BeforeEach
    public void initData() {
        ExtensionSecurityProxy proxy = new ExtensionSecurityProxy();
        proxy.hook(new ExtensionHook(new Model(), new View()));
        this.listener = new SecurityProxyListener(proxy);
        this.test = new TypoSquattingTest(listener);
        Website youtube = new Website("www.youtube.com");
        Website google = new Website("www.google.com");
        Website typoYoutube = new Website("www.youtbe.com", youtube);
        System.out.println(typoYoutube.toString());
        proxy.getWebsites().addAll(List.of(youtube, google, typoYoutube));
    }

    /**
     * The test try to get the listener to assert a custom request
     * where the user want to connect to a visited legitimate hostname
     * The expected result is not blocked and the listener shouldn't
     * modify the response body so the request can be sent to the intended server
     * @throws URIException uri parsing exception
     * @throws HttpMalformedHeaderException malformed header exception
     */
    @Test
    public void accessLegitStoredLegitHostName() throws URIException, HttpMalformedHeaderException {
        HttpMessage message = new HttpMessage(new URI(HTTPS + "www.youtube.com", true));
        message.getRequestHeader().setHeader("Accept", "text/html");

        boolean result = listener.onHttpRequestSend(message);

        Assertions.assertTrue(result);
        Assertions.assertEquals(0, message.getResponseBody().length());
    }

    /**
     * The test try to get the listener to assert a custom request
     * where the user want to connect to a new hostname that is not violate the tests
     * The expected result is not blocked and the listener shouldn't
     * modify the response body so the request can be sent to the intended server
     * In addition, the new non-violated hostname should be stored in the legitimate list
     * @throws URIException uri parsing exception
     * @throws HttpMalformedHeaderException malformed header exception
     */
    @Test
    public void accessLegitNonStoredLegitHostName() throws URIException, HttpMalformedHeaderException {
        HttpMessage message = new HttpMessage(new URI(HTTPS + "www.facebook.com", true));
        message.getRequestHeader().setHeader("Accept", "text/html");

        boolean result = listener.onHttpRequestSend(message);

        Assertions.assertTrue(result);
        Assertions.assertTrue(test.getKnownUrlList().contains("www.facebook.com"));
        Assertions.assertEquals(0, message.getResponseBody().length());
    }

    /**
     * The test try to get the listener to assert a custom request
     * where the user want to connect to a referred of visited legitimate hostname
     * (Usually these type of requests are trying to fetch the resources for the legitimate website)
     * The expected result is not blocked and the listener shouldn't
     * modify the response body so the request can be sent to the intended server
     * In addition, the listener shouldn't store the hostname in legitimate list
     * @throws URIException uri parsing exception
     * @throws HttpMalformedHeaderException malformed header exception
     */
    @Test
    public void accessReferrerOfLegitStoredLegitHostName() throws URIException, HttpMalformedHeaderException {
        HttpMessage message = new HttpMessage(new URI(HTTPS + "www.ads.software-system.com", true));
        message.getRequestHeader().setHeader("Accept", "*/*");
        message.getRequestHeader().setHeader("Referrer", "www.youtube.com");

        boolean result = listener.onHttpRequestSend(message);

        Assertions.assertTrue(result);
        Assertions.assertFalse(test.getKnownUrlList().contains("www.ads.software-system.com"));
        Assertions.assertEquals(0, message.getResponseBody().length());
    }
}
