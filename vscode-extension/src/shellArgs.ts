// Arguments passed through cmd.exe (Windows `shell: true`) are re-parsed by the
// shell, so attacker-controlled file names could inject commands. Reject
// metacharacters outright and quote everything else.
const CMD_UNSAFE = /["%^&|<>!\r\n\0`]/;

export function quoteForCmd(arg: string): string {
  if (CMD_UNSAFE.test(arg)) {
    throw new Error(`Refusing to pass unsafe argument to shell: ${JSON.stringify(arg)}`);
  }
  return /[\s(),;=]/.test(arg) || arg === "" ? `"${arg}"` : arg;
}
