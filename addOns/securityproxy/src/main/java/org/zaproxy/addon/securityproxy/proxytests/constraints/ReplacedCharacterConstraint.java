package org.zaproxy.addon.securityproxy.proxytests.constraints;

public class ReplacedCharacterConstraint implements TypoSquattingConstraint{

    @Override
    public boolean passedConstraint(String original, String typo) {
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
