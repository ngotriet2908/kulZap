package org.zaproxy.addon.securityproxy.proxytests.constraints;

import org.zaproxy.addon.securityproxy.proxytests.constraints.crackLib.CrackLib;
import org.zaproxy.addon.securityproxy.proxytests.constraints.crackLib.Packer;

import java.io.IOException;

public class CrackLibPasswConstraint implements SafePasswordConstraint{
    @Override
    public boolean passedConstraint(String password) {
        try {
            Packer p = new Packer("test","rw");
            //CrackLib cl = new CrackLib();
            return CrackLib.fascistLook(p, password, null);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return false;
    }

    @Override
    public String getReason() {
        return "Password fails crackLib";
    }
}
