// Valheim KeyManager DRM Bypasser
// Site UI and file handling
// License: MIT

function triggerDownload(data, filename) {
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([data]));
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
}

function setStatus(text, state) {
    const el = document.getElementById("status");
    el.textContent = text;
    el.className = "status" + (state ? " " + state : "");
}

function handleFileSelect(file) {
    if (!file) return;

    setStatus("Processing " + file.name + "...", "");

    const r = new FileReader();
    r.onload = x => {
        const u = new Uint8Array(x.target.result);

        let ilReport = null;
        try { ilReport = patchIL(u); } catch (_) { /* not a valid .NET PE, fall through */ }

        if (ilReport && ilReport.total > 0) {
            const lines = [
                "IL patch successful! (" + ilReport.total + " patch(es) applied)",
                "  CheckAllowed patched:      " + ilReport.checkAllowedPatched,
                "  Abort scheduler silenced:  " + ilReport.abortSchedulerPatched,
                "  Fatal logger silenced:     " + ilReport.fatalLoggerSilenced,
                "\n" +
                "⏬ patched_" + file.name + " download started."
            ];
            if (ilReport.warnings.length > 0) {
                lines.push("Warnings:");
                ilReport.warnings.forEach(w => lines.push("  \u26a0 " + w));
            }
            setStatus(lines.join("\n"), "success");
            triggerDownload(u, "patched_" + file.name);
            return;
        }

        if (ilReport && ilReport.keyManagerDetected && ilReport.total === 0) {
            const lines = ["KeyManager detected but no patches were applied.", "Warnings:"];
            ilReport.warnings.forEach(w => lines.push("  \u26a0 " + w));
            setStatus(lines.join("\n"), "warning");
            return;
        }

        for (const patternInfo of magicPatterns) {
            const p = h(patternInfo.pattern);
            const i = fnd(u, p);
            if (i !== -1) {
                u[i + patternInfo.offset] = patternInfo.patchValue;
                setStatus("Byte-pattern patch successful! Downloading patched file...", "success");
                triggerDownload(u, "patched_" + file.name);
                return;
            }
        }

        setStatus(
            "No patchable KeyManager pattern found." +
            " This mod may not use KeyManager DRM or the protection has changed.",
            "error"
        );
    };
    r.readAsArrayBuffer(file);
}

// Drop zone setup
const dropZone = document.getElementById("drop-zone");
const fileInput = document.getElementById("f");

["dragenter", "dragover", "dragleave", "drop"].forEach(ev => {
    dropZone.addEventListener(ev, e => { e.preventDefault(); e.stopPropagation(); }, false);
});

["dragenter", "dragover"].forEach(ev => {
    dropZone.addEventListener(ev, () => dropZone.classList.add("highlight"), false);
});

["dragleave", "drop"].forEach(ev => {
    dropZone.addEventListener(ev, () => dropZone.classList.remove("highlight"), false);
});

dropZone.addEventListener("drop", e => {
    const files = e.dataTransfer.files;
    if (files.length) handleFileSelect(files[0]);
}, false);

dropZone.addEventListener("click", () => fileInput.click());

fileInput.addEventListener("change", function() {
    if (this.files.length > 0) handleFileSelect(this.files[0]);
});
