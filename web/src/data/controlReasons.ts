/// The device's constant control reasons, rendered as the sentence an operator needs.
///
/// A token this build does not know is shown verbatim: a reason must never be swallowed, and
/// the device stays the authority on what it refuses. The tokens come from the device's
/// `control.get` answer and from its `control.set` refusals.

export const REASON_TEXT: Record<string, string> = {
  write_settings_required:
    "the user has not allowed this app to modify system settings; grant it on the device's setup screen",
  policy_access_required:
    "the user has not granted Do Not Disturb access; grant it on the device's setup screen",
  reboot_requires_privilege:
    "rebooting needs the signature-level REBOOT permission; only a system or device-owner build can do it",
  wifi_setter_removed:
    "Android returns false from Wi-Fi toggles for an app targeting Android 10+, so the system UI owns Wi-Fi",
  bluetooth_setter_removed:
    "Android ignores Bluetooth toggles from an app targeting Android 13+, so the system UI owns Bluetooth",
  mobile_data_setter_signature_gated:
    "mobile data needs MODIFY_PHONE_STATE, a signature-level permission an installed app cannot hold",
  night_mode_setter_signature_gated:
    "night mode needs MODIFY_DAY_NIGHT_MODE, a signature-level permission an installed app cannot hold",
  rotation_requires_system_ui:
    "the rotation lock belongs to the system UI; an installed app has no setter for it",
  platform_read_failed: "the platform would not produce this reading",
  no_bluetooth_adapter: "this device reports no Bluetooth adapter",
  no_telephony_data: "this device has no mobile-data radio",
  battery_not_reported: "the battery does not report a capacity",
  brightness_not_applied: "the settings provider accepted the write but the value did not stick",
  brightness_mode_automatic:
    "automatic brightness governs the display and could not be confirmed off, so a stored value would not hold",
  brightness_not_applied_mode_left_manual:
    "the brightness did not stick, and automatic brightness could not be turned back on, so the display is left in manual mode",
  read_back_unavailable:
    "the platform accepted the write but would not report the value back, so the change cannot be confirmed",
  read_back_unavailable_mode_left_manual:
    "the change could not be confirmed, and automatic brightness could not be turned back on, so the display is left in manual mode",
  write_settings_required_mode_left_manual:
    "the system-settings grant was withdrawn mid-change, and automatic brightness could not be turned back on, so the display is left in manual mode",
  volume_not_applied: "the audio service did not apply the volume",
  dnd_not_applied: "the interruption filter did not change",
  volume_max_unreadable: "the device would not report its music volume range",
  not_reported: "the device did not report it",
};

export function reasonText(reason: string): string {
  return REASON_TEXT[reason] ?? reason;
}
