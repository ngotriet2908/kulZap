package org.zaproxy.addon.securityproxy.proxytests.constraints;

import java.io.FileNotFoundException;
import java.io.IOException;

public interface SafePasswordConstraint {

    public abstract boolean passedConstraint(String password);
    public abstract String getReason();
}
