package org.zaproxy.addon.simpleexample.tests;

import java.util.ArrayList;
import java.util.List;

public class TypoSquater {
    private List<TypoSquatingTest> tests;
    public TypoSquater() {
        this.tests = new ArrayList<>();
    }
    public TypoSquater(List<TypoSquatingTest> tests) {
        this.tests = tests;
    }

    public void setTests(List<TypoSquatingTest> tests) {
        this.tests = tests;
    }

    public void addtest(TypoSquatingTest test) {
        this.tests.add(test);
    }

    public List<TypoSquatingTest> getTests() {
        return tests;
    }
    public String isTypoOfDomain(String domain) {
        for (TypoSquatingTest test : tests) {
            String foundDomain = test.isTypoOfDomain(domain);
            if (!foundDomain.equals("no known url")) return foundDomain;
        }
        return "no known url";
    }
}
