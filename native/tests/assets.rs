//! Static assets `tauri.conf.json` promises.
//!
//! A missing Windows icon is invisible on every other platform: `tauri-build` embeds a `.ico`
//! into the executable's resources only when compiling for Windows, so the shell compiles
//! fine on Linux and macOS and fails on the Windows runner alone. Checking the declared paths
//! here turns that into a failure on whichever platform runs the tests.

use std::path::Path;

use serde_json::Value;

fn tauri_config() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tauri.conf.json");
    let text = std::fs::read_to_string(&path).expect("read tauri.conf.json");
    serde_json::from_str(&text).expect("tauri.conf.json is JSON")
}

#[test]
fn every_icon_the_config_declares_exists() {
    let icons = tauri_config()["bundle"]["icon"]
        .as_array()
        .expect("bundle.icon is a list")
        .clone();
    assert!(!icons.is_empty(), "the desktop shell declares no icons");

    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for icon in icons {
        let relative = icon.as_str().expect("an icon path is a string");
        assert!(
            root.join(relative).is_file(),
            "tauri.conf.json declares {relative}, but the file does not exist"
        );
    }
}

#[test]
fn a_windows_icon_is_available_where_tauri_build_looks_for_it() {
    // `tauri-build` embeds the first `.ico` in `bundle.icon`, then falls back to
    // `icons/icon.ico`, and fails the Windows build when neither file exists.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let declared = tauri_config()["bundle"]["icon"]
        .as_array()
        .expect("bundle.icon is a list")
        .clone();
    let declared_ico = declared
        .iter()
        .filter_map(Value::as_str)
        .find(|icon| icon.ends_with(".ico"));

    let available = match declared_ico {
        Some(icon) => root.join(icon).is_file(),
        None => root.join("icons/icon.ico").is_file(),
    };
    assert!(
        available,
        "no .ico is declared and icons/icon.ico is missing; the Windows build would fail"
    );
}
