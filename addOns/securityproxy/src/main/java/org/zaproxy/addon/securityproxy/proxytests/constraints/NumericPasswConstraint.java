package org.zaproxy.addon.securityproxy.proxytests.constraints;

import java.text.CharacterIterator;
import java.text.StringCharacterIterator;

public class NumericPasswConstraint implements SafePasswordConstraint{

    @Override
    public boolean passedConstraint(String password) {
        CharacterIterator it = new StringCharacterIterator(password);
        while (it.current() != CharacterIterator.DONE) {
            if (!Character.isDigit(it.current())) return true;
            it.next();
        }
        return false;
    }

    @Override
    public String getReason() {
        return "Password only contains numbers";
    }
}
