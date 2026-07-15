import subprocess


class Probe:
    def gdb_args(self, run_argv: list[str]) -> list[str]:
        args = ["gdb", "-batch"]
        args += ["--args", *run_argv]
        return args


def exact_pr_129_shape(probe: Probe, run_argv, stdin, timeout):
    args = probe.gdb_args(run_argv)
    return subprocess.run(
        args, input=stdin, capture_output=True, timeout=timeout,
    )


def direct_list(user_argument):
    return subprocess.run(["tool", user_argument], shell=False)


def direct_tuple(user_argument):
    return subprocess.check_output(("tool", user_argument))


def assigned_list(user_argument):
    argv = ["tool", user_argument]
    return subprocess.Popen(argv)


def static_shell_string():
    return subprocess.run("tool --status", shell=True)
