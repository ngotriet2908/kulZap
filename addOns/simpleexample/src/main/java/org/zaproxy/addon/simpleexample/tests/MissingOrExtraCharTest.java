package org.zaproxy.addon.simpleexample.tests;

import org.zaproxy.addon.simpleexample.ExtensionSimpleExample;

abstract public class MissingOrExtraCharTest extends TypoSquatingTest {
    public MissingOrExtraCharTest(ExtensionSimpleExample extension) {
        super(extension);
    }

    protected boolean hasMissingChar(String full, String missing){
        int n=full.length();
        if (! (missing.length()+1==n)) return false;
        int skip = 0;
        for (int i = 0; i < n; i++) {
            if (skip==0 && i==n-1) return true;
            if (!(full.charAt(i)==missing.charAt(i-skip))) {
                skip+=1;
                if (skip>1) return false;
            }
        }
        return true;
    }
}
