package org.zaproxy.addon.securityproxy.proxytests;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.securityproxy.ExtensionSecurityProxy;
import org.zaproxy.addon.securityproxy.SecurityProxyListener;

import java.util.List;

public class TypoSquattingTestTests {
    private TypoSquattingTest test;

    private static final String HTTPS = "https://";

    /**
     * Initialize the google and youtube as visited legitimate
     * hostname. Also initialize TypoSquattingTest.
     */
    @BeforeEach
    public void initData() {
        ExtensionSecurityProxy proxy = new ExtensionSecurityProxy();
        SecurityProxyListener listener = new SecurityProxyListener(proxy);
        this.test = new TypoSquattingTest(listener);
        Website youtube = new Website("www.youtube.com");
        Website google = new Website("www.google.com");
        System.out.println(test.getTestName());
        proxy.getWebsites().addAll(List.of(youtube, google));
    }

    /**
     * Parameterize Test to test whether a custom request with
     * pre-defined legitimate hostnames (stored hostnames and new hostnames)
     * that are expected to pass the TypoSquatting test
     * @param hostname legitimate hostnames
     * @throws URIException uri parsing exception
     * @throws HttpMalformedHeaderException malformed header exception
     */
    @org.junit.jupiter.params.ParameterizedTest
    @ValueSource(strings = {
            "www.youtube.com",
            "www.facebook.com",
            "www.google.com"})
    public void legitHostnameTypoSquattingTest(String hostname) throws URIException, HttpMalformedHeaderException {
        HttpMessage message = new HttpMessage(new URI(HTTPS + hostname, true));
        message.getRequestHeader().setHeader("Accept", "text/html");
        Assertions.assertTrue(this.test.isSafe(message));
    }

    /**
     * Parameterize Test to test whether a custom request with
     * pre-defined TypoSquatting hostnames
     * that are expected to fail the TypoSquatting test
     * @param hostname legitimate hostnames
     * @throws URIException uri parsing exception
     * @throws HttpMalformedHeaderException malformed header exception
     */
    @org.junit.jupiter.params.ParameterizedTest
    @ValueSource(strings = {
                    "www.youtbe.com",
                    "www.youutube.com",
                    "www.gogle.com"})
    public void typoHostnameTypoSquattingTest(String hostname) throws URIException, HttpMalformedHeaderException {
        HttpMessage message = new HttpMessage(new URI(HTTPS + hostname, true));
        message.getRequestHeader().setHeader("Accept", "text/html");
        Assertions.assertFalse(this.test.isSafe(message));
    }

    /**
     * Parameterize Test to test whether a custom request with
     * various TypoSquatting derivation from www.youtube.com
     * that are expected to fail the TypoSquatting test and return www.youtube.com
     * @param hostname legitimate hostnames
     * @throws URIException uri parsing exception
     * @throws HttpMalformedHeaderException malformed header exception
     */
    @org.junit.jupiter.params.ParameterizedTest
    @ValueSource(strings = {
            "www.youtbe.com",
            "www.youtuube.com",
            "www.youutube.com",
            "www.yoAtube.com",
            "www.yotuube.com"})
    public void typoHostnameStringTypoSquattingTest(String hostname) throws URIException, HttpMalformedHeaderException {
        HttpMessage message = new HttpMessage(new URI(HTTPS + hostname, true));
        message.getRequestHeader().setHeader("Accept", "text/html");
        Assertions.assertEquals(this.test.isSafeWithReason(message), "www.youtube.com");
    }
}
