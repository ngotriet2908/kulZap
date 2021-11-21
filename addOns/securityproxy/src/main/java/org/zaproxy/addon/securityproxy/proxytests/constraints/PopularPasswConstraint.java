package org.zaproxy.addon.securityproxy.proxytests.constraints;

import org.parosproxy.paros.Constant;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Scanner;

public class PopularPasswConstraint implements SafePasswordConstraint{
    private static final String POPULAR_PASSW_STRING = "src/main/zapHomeFiles/example/popularPasswords.txt";
    @Override
    public boolean passedConstraint(String password){
        File popPassws = new File(Constant.getZapHome(), POPULAR_PASSW_STRING);
        Scanner scanner = null;
        try {
            scanner = new Scanner(popPassws);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        while (scanner.hasNextLine()){
            if (scanner.nextLine().equals(password)) return false;
        }
        return true;
    }
}
