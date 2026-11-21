// Groovy safe fixture - should not trigger built-in Groovy rules.

def password = System.getenv("DB_PASSWORD")
def author = 'someone-with-a-long-name'

def listTmp() {
    return 'ls -la /tmp'.execute().text
}

def runConstant() {
    new GroovyShell().evaluate("1 + 1")
    Eval.me('2 * 3')
}
