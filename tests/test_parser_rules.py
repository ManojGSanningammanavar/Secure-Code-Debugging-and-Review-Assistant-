from pathlib import Path

from app.analysis.c_parser import parse_c
from app.analysis.log_parser import parse_log
from app.analysis.rules import run_rules

ROOT = Path(__file__).resolve().parent.parent / "data" / "sample_repos" / "brake-ecu"


def _ids(code, path="src/t.c"):
    return {f.rule_id for f in run_rules([parse_c(path, code)])}


def test_parser_extracts_functions_and_metrics():
    pf = parse_c("x.c", "/* c */\nint add(int a, int b)\n{\n    if (a > 0 && b > 0) { return a + b; }\n    return 0;\n}\n")
    assert [f.name for f in pf.functions] == ["add"]
    fn = pf.functions[0]
    assert fn.start_line == 2 and fn.end_line == 6
    assert fn.metrics["cyclomatic"] == 3 and fn.metrics["returns"] == 2


def test_comments_and_strings_do_not_trigger_rules():
    code = 'void f(void)\n{\n    /* strcpy(a, b); */\n    const char *s = "gets(x)";\n    (void)s;\n}\n'
    assert "SC-BUF-01" not in _ids(code)


def test_unbounded_copy_detected():
    assert "SC-BUF-01" in _ids("void f(char *d, const char *s)\n{\n    strcpy(d, s);\n}\n")


def test_off_by_one_detected_and_fixed_version_clean():
    bad = "static int a[4];\nvoid f(void)\n{\n    int i;\n    for (i = 0; i <= 4; i++)\n    {\n        a[i] = 0;\n    }\n}\n"
    assert "SC-BUF-04" in _ids(bad)
    assert "SC-BUF-04" not in _ids(bad.replace("<=", "<"))


def test_malloc_without_null_check_and_leak_on_early_return():
    code = ("int f(int n)\n{\n    char *p = malloc(n);\n    p[0] = 1;\n    if (n > 3)\n    {\n        return 1;\n    }\n"
            "    free(p);\n    return 0;\n}\n")
    assert {"SC-NULL-01", "SC-MEM-02", "SC-MEM-03"} <= _ids(code)


def test_uninitialised_paths():
    code = "int f(int m)\n{\n    int r;\n    if (m) { r = 1; }\n    return r;\n}\n"
    assert "SC-UNINIT-02" in _ids(code)
    assert "SC-UNINIT-02" not in _ids(code.replace("int r;", "int r = 0;"))


def test_for_loop_counter_not_flagged():
    code = "void f(int *a)\n{\n    int i;\n    if (a == 0) { return; }\n    for (i = 0; i < 3; i++)\n    {\n        a[i] = 0;\n    }\n}\n"
    assert not {"SC-UNINIT-01", "SC-UNINIT-02"} & _ids(code)


def test_division_guard_respected():
    bad = "unsigned f(unsigned a, unsigned n)\n{\n    return a / n;\n}\n"
    good = "unsigned f(unsigned a, unsigned n)\n{\n    unsigned r = 0u;\n    if (n != 0u) { r = a / n; }\n    return r;\n}\n"
    assert "SC-DIV-01" in _ids(bad)
    assert "SC-DIV-01" not in _ids(good)


def test_isr_shared_variable_rules():
    code = "static unsigned cnt;\nvoid Tick_ISR(void)\n{\n    cnt++;\n}\nvoid Task(void)\n{\n    cnt = 0u;\n}\n"
    ids = _ids(code)
    assert "SC-ISR-01" in ids and "SC-ISR-02" in ids


def test_switch_without_default_and_assignment_in_condition():
    code = "void f(int x, int y)\n{\n    switch (x)\n    {\n        case 1: y = 2; break;\n    }\n    if (y = 3)\n    {\n        y++;\n    }\n}\n"
    ids = _ids(code)
    assert "SC-CF-01" in ids and "SC-CF-05" in ids


def test_hardcoded_secret_detected_but_not_in_comment():
    assert "SC-SEC-01" in _ids('static const char *password = "hunter22";\n')
    assert "SC-SEC-01" not in _ids('/* password = "hunter22"; */\n')


def test_reference_file_is_clean():
    pf = parse_c("src/util/sensor_filter.c", (ROOT / "src/util/sensor_filter.c").read_text())
    assert run_rules([pf]) == []


def test_repository_aware_nullable_return():
    pfs = [parse_c(str(p.relative_to(ROOT)), p.read_text()) for p in ROOT.rglob("*.c")]
    assert ("SC-NULL-03", "Brake_ApplyChannel") in {(f.rule_id, f.function) for f in run_rules(pfs)}


def test_log_parser_formats():
    log = ("../src/a.c:10:5: warning: 'x' may be used uninitialized [-Wmaybe-uninitialized]\n"
           "[src/b.c:7]: (error) Memory leak: p\n"
           "x.o: in function `f': undefined reference to `g'\n"
           "../src/a.c:11:1: note: declared here\n")
    w = parse_log(log)
    assert len(w) == 3
    assert w[0]["file"] == "src/a.c" and w[0]["line"] == 10 and w[0]["flag"] == "-Wmaybe-uninitialized"
    assert w[1]["tool"] == "cppcheck" and w[2]["tool"] == "linker"
