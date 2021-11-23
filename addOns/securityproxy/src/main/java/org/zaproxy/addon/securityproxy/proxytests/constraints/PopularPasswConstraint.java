package org.zaproxy.addon.securityproxy.proxytests.constraints;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class PopularPasswConstraint implements SafePasswordConstraint{
    private static final String POPULAR_PASSW_STRING_TEST = "src/main/zapHomeFiles/example/popularPasswords.txt";
    private static final String POPULAR_PASSW_STRING = "example/popularPasswords.txt";
    private List<String> popularPasswords;

    private static final Logger LOGGER = LogManager.getLogger(PopularPasswConstraint.class);

    public PopularPasswConstraint() {
        LOGGER.info("start loading popular passwords");
        popularPasswords = new ArrayList<>();

        File popPassws = new File(Constant.getZapHome(), POPULAR_PASSW_STRING);
        if (!popPassws.exists()) {
            popPassws = new File(Constant.getZapHome(), POPULAR_PASSW_STRING_TEST);
        }

        Scanner scanner = null;
        try {
            scanner = new Scanner(popPassws);
            while (scanner.hasNextLine()){
                popularPasswords.add(scanner.nextLine());
            }
            scanner.close();
        } catch (FileNotFoundException e) {
            LOGGER.error(e.getMessage());
        }
        LOGGER.info("Loaded: " + popularPasswords.size() + " popular passwords");
    }

    @Override
    public boolean passedConstraint(String password){
        for(String popularPassword: popularPasswords) {
            if (popularPassword.equals(password)) {
                return false;
            }
        }
        return true;
    }

    @Override
    public String getReason() {
        return "password is in top 500 most popular password";
    }
}
