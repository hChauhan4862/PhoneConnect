# PhoneConnect Android agent

Placeholder: this directory will hold the Kotlin Android agent that enrolls a device and
keeps exactly one foreground connection service with one visible status notification.

Its intended responsibility is to hold the authenticated control connection to the
PhoneConnect server (with boot/network recovery and bounded exponential reconnect), report
bounded telemetry, and expose feature adapters for shell-like commands, files, apps, input,
display, audio, and diagnostics where Android policy permits them. ADB is used only to
sideload/enroll the app, never as the runtime identity or transport.

The agent speaks the shared wire format in `../proto` through generated Kotlin types; it
must not maintain a second, hand-written schema.
