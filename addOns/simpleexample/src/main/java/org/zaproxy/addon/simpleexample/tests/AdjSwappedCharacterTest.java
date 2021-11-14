package org.zaproxy.addon.simpleexample.tests;

import org.zaproxy.addon.simpleexample.ExtensionSimpleExample;

public class AdjSwappedCharacterTest extends TypoSquatingTest{
    public AdjSwappedCharacterTest(ExtensionSimpleExample extension) {
        super(extension);
    }

    @Override
    boolean isTypoOf(String original, String typo) {
        int n=original.length();
        if (! (typo.length()==n)) return false;
        int nError = 0;
        for (int i = 0; i < n-1; i++) {
            if (!(original.charAt(i)==typo.charAt(i))) {
                if (i==n-1) return false;
                if (original.charAt(i+1)==typo.charAt(i) && original.charAt(i)==typo.charAt(i+1)) {
                    nError+=1;
                    i+=1;
                    if (nError >1) return false;
                } else return false;
            }
        }
        return nError == 1;
    }
}
