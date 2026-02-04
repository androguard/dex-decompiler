//! Java source emission: type descriptors to Java names, access flags, etc.

/// Convert DEX type descriptor to Java type name (for source).
/// - V -> void
/// - Z -> boolean, B -> byte, S -> short, C -> char, I -> int, J -> long, F -> float, D -> double
/// - Lpkg/Name; -> pkg.Name
/// - [X -> Java array (e.g. [I -> int[], [[I -> int[][], [Ljava/lang/String; -> java.lang.String[])
pub fn descriptor_to_java(descriptor: &str) -> String {
    if descriptor.is_empty() {
        return String::new();
    }
    let b = descriptor.as_bytes();
    if b[0] == b'[' {
        let inner = descriptor_to_java(&descriptor[1..]);
        format!("{}[]", inner)
    } else if b[0] == b'L' {
        let end = descriptor.find(';').unwrap_or(descriptor.len());
        descriptor[1..end].replace('/', ".")
    } else {
        match b[0] {
            b'V' => "void".into(),
            b'Z' => "boolean".into(),
            b'B' => "byte".into(),
            b'S' => "short".into(),
            b'C' => "char".into(),
            b'I' => "int".into(),
            b'J' => "long".into(),
            b'F' => "float".into(),
            b'D' => "double".into(),
            _ => descriptor.to_string(),
        }
    }
}

/// Format Java access modifiers from DEX access_flags (class or member).
pub fn access_flags_to_java(flags: u32, for_class: bool) -> Vec<&'static str> {
    let mut out = Vec::new();
    if flags & 0x1 != 0 {
        out.push("public");
    }
    if flags & 0x2 != 0 {
        out.push("private");
    }
    if flags & 0x4 != 0 {
        out.push("protected");
    }
    if flags & 0x8 != 0 {
        out.push("static");
    }
    if flags & 0x10 != 0 {
        out.push("final");
    }
    if flags & 0x20 != 0 && !for_class {
        out.push("synchronized");
    }
    if flags & 0x40 != 0 && !for_class {
        out.push("volatile"); // or bridge
    }
    if flags & 0x80 != 0 && !for_class {
        out.push("transient"); // or varargs
    }
    if flags & 0x100 != 0 && !for_class {
        out.push("native");
    }
    if flags & 0x200 != 0 && for_class {
        out.push("interface");
    }
    if flags & 0x400 != 0 {
        out.push("abstract");
    }
    if flags & 0x1000 != 0 {
        out.push("synthetic");
    }
    if flags & 0x10000 != 0 && !for_class {
        // ACC_CONSTRUCTOR - we use name "<init>" for constructor, no keyword
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_void() {
        assert_eq!(descriptor_to_java("V"), "void");
    }

    #[test]
    fn descriptor_primitives() {
        assert_eq!(descriptor_to_java("Z"), "boolean");
        assert_eq!(descriptor_to_java("B"), "byte");
        assert_eq!(descriptor_to_java("S"), "short");
        assert_eq!(descriptor_to_java("C"), "char");
        assert_eq!(descriptor_to_java("I"), "int");
        assert_eq!(descriptor_to_java("J"), "long");
        assert_eq!(descriptor_to_java("F"), "float");
        assert_eq!(descriptor_to_java("D"), "double");
    }

    #[test]
    fn descriptor_class() {
        assert_eq!(descriptor_to_java("Ljava/lang/String;"), "java.lang.String");
        assert_eq!(descriptor_to_java("Lpkg/Cls;"), "pkg.Cls");
        assert_eq!(descriptor_to_java("Lcom/example/Main;"), "com.example.Main");
    }

    #[test]
    fn descriptor_array() {
        assert_eq!(descriptor_to_java("[I"), "int[]");
        assert_eq!(descriptor_to_java("[Ljava/lang/String;"), "java.lang.String[]");
        assert_eq!(descriptor_to_java("[[I"), "int[][]");
        assert_eq!(descriptor_to_java("[[Ljava/lang/Object;"), "java.lang.Object[][]");
    }

    #[test]
    fn descriptor_empty() {
        assert_eq!(descriptor_to_java(""), "");
    }

    #[test]
    fn descriptor_unknown_primitive_unchanged() {
        assert_eq!(descriptor_to_java("X"), "X");
    }

    #[test]
    fn access_flags_class_public_final() {
        let f = access_flags_to_java(0x1 | 0x10, true);
        assert!(f.contains(&"public"));
        assert!(f.contains(&"final"));
        assert_eq!(f.len(), 2);
    }

    #[test]
    fn access_flags_class_interface_abstract() {
        let f = access_flags_to_java(0x200 | 0x400, true);
        assert!(f.contains(&"interface"));
        assert!(f.contains(&"abstract"));
    }

    #[test]
    fn access_flags_method_public_static() {
        let f = access_flags_to_java(0x1 | 0x8, false);
        assert!(f.contains(&"public"));
        assert!(f.contains(&"static"));
    }

    #[test]
    fn access_flags_method_private_native() {
        let f = access_flags_to_java(0x2 | 0x100, false);
        assert!(f.contains(&"private"));
        assert!(f.contains(&"native"));
    }

    #[test]
    fn access_flags_empty() {
        assert!(access_flags_to_java(0, true).is_empty());
        assert!(access_flags_to_java(0, false).is_empty());
    }

    #[test]
    fn access_flags_synchronized_not_for_class() {
        let f = access_flags_to_java(0x20, false);
        assert!(f.contains(&"synchronized"));
        let f_class = access_flags_to_java(0x20, true);
        assert!(!f_class.contains(&"synchronized"));
    }

    #[test]
    fn access_flags_interface_only_for_class() {
        let f = access_flags_to_java(0x200, true);
        assert!(f.contains(&"interface"));
        let f_method = access_flags_to_java(0x200, false);
        assert!(!f_method.contains(&"interface"));
    }
}
