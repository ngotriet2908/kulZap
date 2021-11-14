package org.zaproxy.addon.securityproxy.proxytests.constraints;

import org.zaproxy.addon.securityproxy.proxytests.TypoSquattingTest;

public class AdjSwappedCharacterConstraint implements TypoSquattingConstraint{

    @Override
    public boolean passedConstraint(String original, String typo) {
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
