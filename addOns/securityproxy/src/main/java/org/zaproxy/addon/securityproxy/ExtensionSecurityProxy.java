/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.addon.securityproxy;

import java.awt.CardLayout;
import java.awt.Font;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.stream.Collectors;
import javax.swing.ImageIcon;
import javax.swing.JTextPane;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.securityproxy.proxytests.Website;
import org.zaproxy.zap.extension.brk.impl.http.ProxyListenerBreak;
import org.zaproxy.zap.utils.FontUtils;
import org.zaproxy.zap.view.ZapMenuItem;

/**
 * An example ZAP extension which adds a top level menu item, a pop up menu item and a status panel.
 *
 * <p>{@link ExtensionAdaptor} classes are the main entry point for adding/loading functionalities
 * provided by the add-ons.
 *
 * @see #hook(ExtensionHook)
 */
public class ExtensionSecurityProxy extends ExtensionAdaptor {

    // The name is public so that other extensions can access it
    public static final String NAME = "ExtensionSecurityProxy";

    // The i18n prefix, by default the package name - defined in one place to make it easier
    // to copy and change this example
    protected static final String PREFIX = "securityProxy";

    /**
     * Relative path (from add-on package) to load add-on resources.
     *
     * @see Class#getResource(String)
     */
    private static final String RESOURCES = "resources";

    private static final ImageIcon ICON =
            new ImageIcon(ExtensionSecurityProxy.class.getResource(RESOURCES + "/cake.png"));

    private static final String EXAMPLE_FILE = "example/ExampleFile.txt";
    private static final String POPULAR_URLS_FILE = "example/popularUrls.txt";
    private static final String URL_FILE = "example/Known_URL.txt";
    private static final String WEBSITE_FILE = "example/website.tmp";
    public static final String HTML_TEMPLATE = "example/warning_page.html";
    public static final String REDIRECT_HTML = "example/redirectPage.html";

    private ZapMenuItem menuExample;
    private RightClickMsgMenu popupMsgMenuExample;
    private AbstractPanel statusPanel;
    private SecurityProxyListener listener;

//    private SimpleExampleAPI api;

//    private List<String> knownUrlList;

    private List<Website> knownWebsites;
    private List<Website> typoWebsites;

    private static final Logger LOGGER = LogManager.getLogger(ExtensionSecurityProxy.class);

    public ExtensionSecurityProxy() {
        super(NAME);
        setI18nPrefix(PREFIX);
        listener = new SecurityProxyListener(this);

    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

//        this.api = new SimpleExampleAPI();
//        extensionHook.addApiImplementor(this.api);
        extensionHook.addProxyListener(this.listener);

//        knownUrlList = new ArrayList<>();
//        knownUrlList = new ArrayList<>();

        knownWebsites = new ArrayList<>();
        typoWebsites = new ArrayList<>();

        createOrLoadUrlFile();

        // As long as we're not running as a daemon
        if (getView() != null) {
            extensionHook.getHookMenu().addToolsMenuItem(getMenuExample());
            extensionHook.getHookMenu().addPopupMenuItem(getPopupMsgMenuExample());
            extensionHook.getHookView().addStatusPanel(getStatusPanel());
        }

    }

    @Override
    public boolean canUnload() {
        // The extension can be dynamically unloaded, all resources used/added can be freed/removed
        // from core.
        return true;
    }

    @Override
    public void unload() {
        super.unload();

        // In this example it's not necessary to override the method, as there's nothing to unload
        // manually, the components added through the class ExtensionHook (in hook(ExtensionHook))
        // are automatically removed by the base unload() method.
        // If you use/add other components through other methods you might need to free/remove them
        // here (if the extension declares that can be unloaded, see above method).
    }

    private AbstractPanel getStatusPanel() {
        if (statusPanel == null) {
            statusPanel = new AbstractPanel();
            statusPanel.setLayout(new CardLayout());
            statusPanel.setName(Constant.messages.getString(PREFIX + ".panel.title"));
            statusPanel.setIcon(ICON);
            JTextPane pane = new JTextPane();
            pane.setEditable(false);
            // Obtain (and set) a font with the size defined in the options
            pane.setFont(FontUtils.getFont("Dialog", Font.PLAIN));
            pane.setContentType("text/html");
            pane.setText(Constant.messages.getString(PREFIX + ".panel.msg"));
            statusPanel.add(pane);
        }
        return statusPanel;
    }

    private ZapMenuItem getMenuExample() {
        if (menuExample == null) {
            menuExample = new ZapMenuItem(PREFIX + ".topmenu.tools.title");

            menuExample.addActionListener(
                    e -> {
                        // This is where you do what you want to do.
                        // In this case we'll just show a popup message.
                        exportToUrlFile();
                        View.getSingleton()
                                .showMessageDialog("Exported to url file");
                        // And display a file included with the add-on in the Output tab
                    });
        }
        return menuExample;
    }

    private void createOrLoadUrlFile() {

        LOGGER.log(Level.INFO, "Start CreateOrLoad url file");

        try {
            File f = new File(Constant.getZapHome(), WEBSITE_FILE);
            if (f.createNewFile()) {
                LOGGER.log(Level.INFO,"URL file not exists, create URL file");

            } else {
                LOGGER.log(Level.INFO,"URL exists, loading url file");
                try {
                    FileInputStream fis = new FileInputStream(f);
                    ObjectInputStream ois = new ObjectInputStream(fis);

                    Object obj = ois.readObject();
                    LOGGER.log(Level.INFO, obj);
                    ArrayList<?> ar = (ArrayList<?>) obj;
                    List<Website> websites = new ArrayList<>();
                    LOGGER.log(Level.INFO, "ar size: " + ar.size());

                    for (Object x : ar) {
                        websites.add((Website) x);
                    }

                    for(Website web: websites) {
                        LOGGER.log(Level.INFO, "Loading: " + web.toString());
                    }
                    LOGGER.log(Level.INFO, "Websites size: " + websites.size());

                    this.knownWebsites = websites
                            .stream()
                            .filter(website -> website.getDirectedWebsite() == null)
                            .collect(Collectors.toList());

                    this.typoWebsites = websites
                            .stream()
                            .filter(website -> website.getDirectedWebsite() != null)
                            .collect(Collectors.toList());
                    ois.close();


                } catch(Exception e) {
                    this.knownWebsites = new ArrayList<>();
                    this.typoWebsites = new ArrayList<>();
                }

            }

        } catch (Exception e) {
            this.listener.logToOutput(e.getMessage());
        }
    }

    private void exportToUrlFile() {

        this.listener.logToOutput("Exporting to url file");

        try {
            File f = new File(Constant.getZapHome(), WEBSITE_FILE);
            if (f.createNewFile()) {
                LOGGER.log(Level.INFO,"URL file not exists, create URL file");

            } else {
                LOGGER.log(Level.INFO,"URL exists, loading url file");
                try {
                    FileOutputStream fos = new FileOutputStream(f);
                    ObjectOutputStream oos = new ObjectOutputStream(fos);

                    List<Website> websites = new ArrayList<>();
                    websites.addAll(this.typoWebsites);
                    websites.addAll(this.knownWebsites);

                    oos.writeObject(websites);
                    oos.close();

                    for(Website web: websites) {
                        LOGGER.log(Level.INFO, "Writing: " + web.toString());
                    }

                } catch(Exception e) {
                    this.knownWebsites = new ArrayList<>();
                    this.typoWebsites = new ArrayList<>();
                }

            }

        } catch (Exception e) {
            this.listener.logToOutput(e.getMessage());
        }
    }


    private RightClickMsgMenu getPopupMsgMenuExample() {
        if (popupMsgMenuExample == null) {
            popupMsgMenuExample =
                    new RightClickMsgMenu(
                            this, Constant.messages.getString(PREFIX + ".popup.title"));
        }
        return popupMsgMenuExample;
    }


    public List<String> getKnownUrlList() {
        return this.knownWebsites
                .stream()
                .map(Website::getHost)
                .collect(Collectors.toList());
    }

    public void addTypoHost(String host, Website origin) {
        this.typoWebsites.add(new Website(host, origin));
    }

    public boolean addKnownHost(String host) {
        for (Website web: this.knownWebsites) {
            if (web.getHost().equals(host)) {
                return false;
            }
        }
        this.knownWebsites.add(new Website(host));
        return true;
    }

    public Website getKnownWebsite(String host) {
        for(Website web: this.knownWebsites) {
            if (web.getHost().equals(host)) {
                return web;
            }
        }
        return null;
    }

    public boolean isTypoWebsite(String host) {
        for(Website web: this.typoWebsites) {
            if (web.getHost().equals(host)) {
                return true;
            }
        }
        return false;
    }

    public List<Website> getKnownWebsites() {
        return knownWebsites;
    }

    public List<Website> getTypoWebsites() {
        return typoWebsites;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(PREFIX + ".desc");
    }
}
