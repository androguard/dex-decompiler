//! Fidelity checks against the AndroguardTest APK (`TestDefault`).
//!
//! Covers debug-typed numeric locals (`testDouble` / unused consts in `test_base`),
//! `synchronized` + try-in-loop (`pouet2`), `while (true)` + catch-continue (`foo2`),
//! and folded arithmetic.

use std::path::PathBuf;

use dex_decompiler::{load_dexes_from_path, Decompiler};

fn androguard_test_apk() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
        "../androguard/tests/data/AndroguardTest/app/build/outputs/apk/debug/app-debug.apk",
    )
}

fn decompile_method(class_name: &str, method_name: &str) -> String {
    let path = androguard_test_apk();
    assert!(
        path.is_file(),
        "missing AndroguardTest apk at {}",
        path.display()
    );
    let dexes = load_dexes_from_path(&path).unwrap_or_else(|e| panic!("load apk: {e}"));
    let simple = class_name.rsplit('.').next().unwrap_or(class_name);
    for dex in &dexes {
        let dc = Decompiler::new(dex);
        if let Some(encoded) = dc.find_method(class_name, method_name) {
            return dc
                .decompile_method(&encoded, Some(simple), Some(class_name))
                .unwrap_or_else(|e| panic!("decompile {class_name}#{method_name}: {e}"));
        }
    }
    panic!("method not found: {class_name}#{method_name}");
}

/// Needles must appear in order. A later pass that swaps the loop and the try,
/// or that retypes an earlier local, fails even if every token is still present.
fn assert_in_order(src: &str, needles: &[&str]) {
    let mut rest = src;
    for needle in needles {
        match rest.find(needle) {
            Some(at) => rest = &rest[at + needle.len()..],
            None => panic!("missing `{needle}` (in order) in:\n{src}"),
        }
    }
}

#[test]
fn test_double_keeps_debug_types_and_names() {
    let src = decompile_method("androguard.test.TestDefault", "testDouble");
    // Full debug-name matrix. Register reuse (`double f` then `float gettype`,
    // `double i` vs later ints) must not collapse to the last type or to `int`.
    assert_in_order(
        &src,
        &[
            "double f = -5.0;",
            "double g = -4.0;",
            "double h = -3.0;",
            "double i = -2.0;",
            "double j = -1.0;",
            "double k = 0.0;",
            "double l = 1.0;",
            "double m = 2.0;",
            "double n = 3.0;",
            "double o = 4.0;",
            "double p = 5.0;",
            "long ff = -5L;",
            "long gg = -4L;",
            "long hh = -3L;",
            "long ii = -2L;",
            "long jj = -1L;",
            "long kk = 0L;",
            "long ll = 1L;",
            "long mm = 2L;",
            "long nn = 3L;",
            "long oo = 4L;",
            "long pp = 5L;",
            "float fff = -5.0f;",
            "float ggg = -4.0f;",
            "float hhh = -3.0f;",
            "float iii = -2.0f;",
            "float jjj = -1.0f;",
            "float kkk = 0.0f;",
            "float lll = 1.0f;",
            "float mmm = 2.0f;",
            "float nnn = 3.0f;",
            "float ooo = 4.0f;",
            "float ppp = 5.0f;",
            "double abc = 65534.0;",
            "double def = 65535.0;",
            "double ghi = 65536.0;",
            "double jkl = 65537.0;",
            "double mno = 32769.0;",
            "double pqr = 32768.0;",
            "double stu = 32767.0;",
            "double vwx = 32766.0;",
            "long aabc = 65534L;",
            "long adef = 65535L;",
            "long aghi = 65536L;",
            "long ajkl = 65537L;",
            "long amno = 32769L;",
            "long apqr = 32768L;",
            "long astu = 32767L;",
            "long avwx = 32766L;",
            "float babc = 65534.0f;",
            "float bdef = 65535.0f;",
            "float bghi = 65536.0f;",
            "float bjkl = 65537.0f;",
            "float bmno = 32769.0f;",
            "float bpqr = 32768.0f;",
            "float bstu = 32767.0f;",
            "float bvwx = 32766.0f;",
            "double abcd = 5346952.0;",
            "long dcba = 5346952L;",
            "float cabd = 5346952.0f;",
            "double zabc = 65534.5;",
            "double zdef = 65535.5;",
            "double zghi = 65536.5;",
            "double zjkl = 65537.5;",
            "double zmno = 32769.5;",
            "double zpqr = 32768.5;",
            "double zstu = 32767.5;",
            "double zvwx = 32766.5;",
            "float xabc = 65534.5f;",
            "float xdef = 65535.5f;",
            "float xghi = 65536.5f;",
            "float xjkl = 65537.5f;",
            "float xmno = 32769.5f;",
            "float xpqr = 32768.5f;",
            "float xstu = 32767.5f;",
            "float xvwx = 32766.5f;",
            "float ymno = -5.0f;",
            "float ypqr = -65535.0f;",
            "float ystu = -65536.0f;",
            // float rounds; the following double must stay a distinct local.
            "float yvwx = -123456790519087104.0f;",
            "double yvwx2 = -123456789123456784.0;",
            "int boom = -606384730;",
            "float reboom = -123456790519087104.0f;",
            "float gettype = boom + 2 + 3.5f;",
            "System.out.println(gettype);",
        ],
    );
    let int_decls: Vec<&str> = src
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("int "))
        .collect();
    assert_eq!(
        int_decls,
        ["int boom = -606384730;"],
        "numeric locals painted as int:\n{src}"
    );
}

#[test]
fn pouet2_matches_synchronized_loop() {
    let src = decompile_method("androguard.test.TestDefault", "pouet2");
    assert!(
        src.contains("public synchronized int pouet2()"),
        "expected a synchronized method, got:\n{src}"
    );
    assert_in_order(
        &src,
        &[
            "int i = 0;",
            "int j = 10;",
            "System.out.println(\"test\");",
            "while (i < j)",
            "try {",
            "i = j++ / i;",
            "catch (RuntimeException",
            "i = 10;",
            "this.value = i;",
            "return 90;",
        ],
    );
    assert!(
        !src.contains("monitor-enter") && !src.contains("monitor-exit"),
        "raw monitors left in pouet2:\n{src}"
    );
    assert!(
        !src.contains("continue"),
        "pouet2 catch is the last statement of the loop:\n{src}"
    );
    assert!(
        !src.contains("this.value = j"),
        "post-increment copy landed on the wrong local:\n{src}"
    );
}

#[test]
fn foo4_try_stays_inside_the_loop() {
    let src = decompile_method("androguard.test.TestDefault", "foo4");
    assert_in_order(
        &src,
        &[
            "while (i < j)",
            "try {",
            "i = j++ / i;",
            "catch (RuntimeException",
            "i = 10;",
            "return j;",
        ],
    );
    assert!(
        !src.contains("while (true)"),
        "catch join became an empty loop:\n{src}"
    );
    assert!(
        !src.contains("handler at code unit"),
        "catch body was not recovered:\n{src}"
    );
    let while_at = src.find("while (i < j)").expect("while");
    let try_at = src.find("try {").expect("try");
    assert!(
        try_at > while_at,
        "try wrapped the loop instead of sitting inside it:\n{src}"
    );
}

#[test]
fn foobis_catch_continues_and_exits_on_ten() {
    let src = decompile_method("androguard.test.TestDefault", "foobis");
    assert_in_order(
        &src,
        &[
            "while (i < j && i != 10)",
            "try {",
            "i = j++ / i;",
            "catch (RuntimeException",
            "i = 10;",
            "continue;",
            "return j;",
        ],
    );
    assert!(
        !src.contains("while (true)"),
        "loop was rewritten:\n{src}"
    );
    let catch_at = src.find("catch (RuntimeException").expect("catch");
    let cont_at = src.find("continue;").expect("continue");
    assert!(
        cont_at > catch_at,
        "continue is not in the catch:\n{src}"
    );
}

#[test]
fn main_switch_keeps_case_bodies() {
    let src = decompile_method("androguard.test.TestDefault", "main");
    assert_in_order(
        &src,
        &[
            "switch (a)",
            "case 1:",
            "case 2:",
            "1 || 2",
            "case 3:",
            "3 || ",
            "case 4:",
            "default:",
            "\"4\"",
            "case 5:",
            "\"5\"",
            "}",
            "new ",
        ],
    );
    let tail = src.split("switch (a)").nth(1).expect("switch");
    let close = tail.find("        }").expect("switch close");
    assert!(
        !tail[..close].contains("TestInnerClass"),
        "code after the switch was swallowed into a case:\n{src}"
    );
    assert!(
        tail[close..].contains("TestInnerClass"),
        "constructor calls after the switch were dropped:\n{src}"
    );
}

#[test]
fn foo2_matches_while_true_try() {
    let src = decompile_method("androguard.test.TestDefault", "foo2");
    assert_in_order(
        &src,
        &[
            "while (true)",
            "if (i < j)",
            "try {",
            "i = j++ / i;",
            "catch (RuntimeException",
            "i = 10;",
            "continue;",
            "if (i == 0)",
            "return j;",
        ],
    );
    assert!(!src.contains("== null"), "index compared as reference:\n{src}");
    assert!(
        !src.contains("if (true)"),
        "while (true) was wrapped again:\n{src}"
    );
    assert!(
        !src.contains("int i =") && !src.contains("int j ="),
        "parameters were shadowed:\n{src}"
    );
}

#[test]
fn test_base_folds_useless_expression() {
    let src = decompile_method("androguard.test.TestDefault", "test_base");
    assert_in_order(
        &src,
        &[
            "int y = 0;",
            "double sd = -6.0;",
            "double zz = -5.0;",
            "double yy = -4.0;",
            "double xx = -3.0;",
            "double w = -2.0;",
            "double x = -1.0;",
            "double k = 0.0;",
            "double d = 1.0;",
            "double b = 2.0;",
            "double c = 3.0;",
            "double f = 4.0;",
            "double z = 5.0;",
            "double cd = 6.0;",
            "float g = 4.2f;",
            "double useless = g * c + b - y + d;",
        ],
    );
    assert_eq!(
        src.lines().filter(|l| l.contains("useless")).count(),
        1,
        "arithmetic was not fully folded:\n{src}"
    );
}

#[test]
fn test_base_try_is_not_the_rest_of_the_method() {
    let src = decompile_method("androguard.test.TestDefault", "test_base");
    assert_in_order(
        &src,
        &[
            "int[] arr0 = new int[5];",
            "arr0[6] = 1;",
            "System.out.println(\"boom\");",
            "if (this.value > 0)",
            "switch (this.value)",
            "this.pouet()",
            "this.pouet2()",
            "this.pouet3()",
            "return ",
        ],
    );
    let catch_at = src
        .find("catch (ArrayIndexOutOfBoundsException")
        .expect("catch");
    let after_catch = &src[catch_at..];
    let close = after_catch.find("\n        }").expect("catch close");
    let catch_body = &after_catch[..close];
    assert!(
        !catch_body.contains("switch"),
        "if/switch fell into the catch:\n{catch_body}"
    );
    assert!(
        !catch_body.contains("this.value2"),
        "post-try assign fell into the catch:\n{catch_body}"
    );
}

fn decompile_test_default_class() -> String {
    let path = androguard_test_apk();
    assert!(path.is_file(), "missing apk at {}", path.display());
    let dexes = load_dexes_from_path(&path).unwrap_or_else(|e| panic!("load apk: {e}"));
    for dex in &dexes {
        let dc = Decompiler::new(dex);
        for cd in dex.class_defs().flatten() {
            let Ok(ty) = dex.get_type(cd.class_idx) else {
                continue;
            };
            if ty.as_str() != "Landroguard/test/TestDefault;" {
                continue;
            }
            return dc
                .decompile_class(&cd)
                .unwrap_or_else(|e| panic!("decompile class: {e}"));
        }
    }
    panic!("TestDefault class");
}

#[test]
fn testdefault_imports_printstream_and_separates_methods() {
    let src = decompile_test_default_class();
    assert!(
        src.contains("import java.io.PrintStream;"),
        "missing PrintStream import:\n{}",
        src.lines().take(12).collect::<Vec<_>>().join("\n")
    );
    assert!(
        src.contains("}\n\n    "),
        "expected a blank line between methods"
    );
    assert!(
        src.contains("PrintStream "),
        "PrintStream should still be used as a simple name"
    );
}

#[test]
fn testdefault_field_inits_are_not_copied_into_every_constructor() {
    let src = decompile_test_default_class();
    assert!(
        src.contains("public int[] tab = new int[]{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };"),
        "tab initializer should live on the field:\n{}",
        src.lines().take(20).collect::<Vec<_>>().join("\n")
    );
    assert!(
        src.contains("private int test = 10;"),
        "test initializer should live on the field"
    );
    assert!(
        src.contains("public int test3 = 30;"),
        "test3 initializer should live on the field"
    );
    let ctor = src
        .split("public TestDefault()")
        .nth(1)
        .and_then(|s| s.split("public TestDefault(").next())
        .expect("default ctor");
    assert!(
        !ctor.contains("this.tab"),
        "default ctor still assigns tab:\n{ctor}"
    );
    assert!(
        !ctor.contains("this.test = 10"),
        "default ctor still assigns the field initializer:\n{ctor}"
    );
    assert!(
        ctor.contains("this.value = 100"),
        "constructor body was dropped:\n{ctor}"
    );
    assert!(
        src.contains("this.test = 5;"),
        "double ctor should still override test"
    );
}
