#[macro_export]
/// Creates a HashMap containing the arguments
///
/// - Create a HashMap containing a given list of elements:
/// ```
/// let m = hashmap!["five" => 5, "six" => 6];
///
/// assert_eq!(*m.get(&"five").unwrap(), 5);
/// assert_eq!(*m.get(&"six").unwrap(), 6);
/// ```
macro_rules! hashmap {
    ($( $key: expr => $val: expr ),*) => {{
         let mut map = ::std::collections::HashMap::new();
         $( map.insert($key, $val); )*
         map
    }}
}

/// verify that an expression matches a patter
macro_rules! matches {
    ($e:expr, $p:pat) => (
        match $e {
            $p => true,
            _ => false
        }
    )
}
