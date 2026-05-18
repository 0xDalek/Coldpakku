// Connection page. Opens in a regular tab (not a popup) because extension
// popups close when they lose focus, which would cancel the WebSerial
// dialog before the user can pick anything.
//
// Flow:
//   1) User presses "Pick port" -> navigator.serial.requestPort()
//   2) If a valid port is picked, the SW picks it up via getPorts() and
//      opens the session with the GBA (popup-connect message).
//   3) We display the address returned by the GBA and allow closing.

export {};

const $ = (id: string) => document.getElementById(id) as HTMLElement;

function show(stepId: "pick" | "busy" | "ok" | "error") {
  for (const id of ["pick", "busy", "ok", "error"]) {
    $(`step-${id}`).hidden = id !== stepId;
  }
}

function setError(msg: string) {
  ($("err-msg") as HTMLParagraphElement).textContent = msg;
  show("error");
}

async function pickAndConnect() {
  try {
    show("pick");
    // requestPort needs a user gesture; we're inside a click handler, so
    // the context is alive. No filters: the user picks the port manually
    // (the Pico's VID varies depending on firmware).
    const port = await navigator.serial.requestPort();
    void port;

    show("busy");
    const r = await chrome.runtime.sendMessage({ kind: "popup-connect" });
    if (!r?.ok) {
      setError(r?.error ?? "Could not open the session with the Game Boy.");
      return;
    }

    const state = await chrome.runtime.sendMessage({ kind: "popup-state" });
    ($("addr") as HTMLSpanElement).textContent = state?.address ?? "(?)";
    show("ok");
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    if (msg.includes("No port selected")) {
      setError(
        "You did not pick any port. Press 'Pick port' again and select the Pico's COM in the browser dialog.",
      );
    } else {
      setError(msg);
    }
  }
}

$("btn-pick").addEventListener("click", () => {
  void pickAndConnect();
});
$("btn-retry").addEventListener("click", () => {
  show("pick");
});
$("btn-close").addEventListener("click", () => {
  window.close();
});
