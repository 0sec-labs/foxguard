import subprocess


def unknown_command(command):
    return subprocess.run(command)


def dynamic_executable(command):
    return subprocess.run([command], shell=False)


def argv(value) -> list[str]:
    return [value]


def misleading_typed_builder(user):
    return subprocess.run(argv(user))


def replaced_executable(user):
    args = ["tool", "--status"]
    args[0] = user
    return subprocess.run(args)


def cleared_argv(user):
    args = ["tool"]
    args.clear()
    args.append(user)
    return subprocess.run(args)


class Evil:
    def gdb_args(self, user):
        return user


def colliding_external_receiver(evil: Evil, user):
    return subprocess.run(evil.gdb_args(user))


class SafeProbe:
    def gdb_args(self, values: list[str]) -> list[str]:
        return ["gdb", *values]


def typed_scope(probe: SafeProbe):
    return probe.gdb_args([])


def cross_scope_receiver_collision(probe, user):
    return subprocess.run(probe.gdb_args(user))


def unrelated_safe_argv_scope():
    cross_scope_args = ["tool"]
    return cross_scope_args


def unrelated_argv_parameter(cross_scope_args):
    return subprocess.run(cross_scope_args)


def unrelated_constant_scope():
    cross_scope_command = "tool"
    return cross_scope_command


def unrelated_command_parameter(cross_scope_command):
    return subprocess.run(cross_scope_command)


def assignment_after_sink(args):
    subprocess.run(args)
    args = ["tool"]
    return args


def escaped_alias(user):
    args = ["tool"]
    alias = args
    alias.clear()
    args.append(user)
    return subprocess.run(args)


def escaped_unknown_mutator(user):
    args = ["tool"]
    mutate(args, user)
    return subprocess.run(args)


def untyped_builder(build, value):
    args = build(value)
    return subprocess.run(args, shell=False)


def shell_list(value):
    return subprocess.run(["tool", value], shell=True)


def dynamic_shell(value, use_shell):
    return subprocess.run(["tool", value], shell=use_shell)


def formatted_shell(value):
    return subprocess.run(f"tool {value}")


def concatenated_shell(value):
    return subprocess.run("tool " + value, shell=False)
