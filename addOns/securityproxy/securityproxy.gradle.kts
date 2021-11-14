description = "The security addons that ensure Typosquatting prevention."

zapAddOn {
    addOnName.set("Security Proxy")
    zapVersion.set("2.11.0")

    manifest {
        author.set("KUL Group 8")
    }
}

crowdin {
    configuration {
        val resourcesPath = "org/zaproxy/addon/${zapAddOn.addOnId.get()}/resources/"
        tokens.put("%messagesPath%", resourcesPath)
        tokens.put("%helpPath%", resourcesPath)
    }
}
