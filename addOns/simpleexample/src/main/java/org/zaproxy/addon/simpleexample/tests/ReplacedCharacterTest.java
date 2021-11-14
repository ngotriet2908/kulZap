package org.zaproxy.addon.simpleexample.tests;

import org.zaproxy.addon.simpleexample.ExtensionSimpleExample;

public class ReplacedCharacterTest extends TypoSquatingTest{

    public ReplacedCharacterTest(ExtensionSimpleExample extension) {
        super(extension);
    }

    @Override
    public boolean isTypoOf(String original, String typo) {
        int n=original.length();
        if (! (typo.length()==n)) return false;
        int nError = 0;
        for (int i = 0; i < n; i++) {
            if (!(original.charAt(i)==typo.charAt(i))) {
                nError +=1;
                if (nError >1) return false;
            }
        }
        return nError == 1;
    }
}
