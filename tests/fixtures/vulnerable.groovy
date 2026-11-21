// Groovy vulnerable fixture: one issue per rule.

def password = "hunter2hunter2"

def listDir(String dir) {
    return "ls ${dir}".execute().text
}

def runScript(String code) {
    new GroovyShell().evaluate(code)
}
