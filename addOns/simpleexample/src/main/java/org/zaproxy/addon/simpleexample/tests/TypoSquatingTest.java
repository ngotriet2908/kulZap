package org.zaproxy.addon.simpleexample.tests;

import org.zaproxy.addon.simpleexample.ExtensionSimpleExample;

import java.util.ListIterator;

public abstract class TypoSquatingTest {
    private ExtensionSimpleExample extension;

    public TypoSquatingTest(ExtensionSimpleExample extension) {
        this.extension = extension;
    }

    public String isTypoOfDomain(String domain) {
        for (String goodDomain : extension.getKnownUrlList()) {
            if (isTypoOf(goodDomain, domain)) return goodDomain;
        }
        return "no known url";
    }
    abstract boolean isTypoOf(String original,String typo);
}