// Magic byte patterns with their corresponding patch information
const magicPatterns = [
    {
        pattern: "012B01160D092C0820E54959C8252B06",
        offset: 6,
        patchValue: 0x2D
    }
    // Future patterns can be added here with their corresponding offset and patch value
];

function h(x) { 
    return x.match(/.{1,2}/g).map(v => parseInt(v, 16)); 
}

function fnd(buf, p) {
    for (let i = 0; i <= buf.length - p.length; i++) {
        let m = 1;
        for (let j = 0; j < p.length; j++) {
            if (buf[i + j] != p[j]) { m = 0; break; }
        }
        if (m) return i;
    }
    return -1;
}

// Handle file selection via input or drag and drop
function handleFileSelect(e) {
    const file = e.target.files[0] || e.dataTransfer.files[0];
    const status = document.getElementById("status");
    if (!file) return;

    status.innerText = "Processing...";

    let r = new FileReader();
    r.onload = x => {
        let u = new Uint8Array(x.target.result);
        
        // Iterate through all magic patterns
        for (let patternInfo of magicPatterns) {
            let p = h(patternInfo.pattern);
            let i = fnd(u, p);

            if (i != -1) {
                // Apply the patch
                u[i + patternInfo.offset] = patternInfo.patchValue;
                status.innerText = "Success! Patching complete. Starting download...";
                status.style.color = "#4dff88";

                let a = document.createElement("a");
                a.href = URL.createObjectURL(new Blob([u]));
                a.download = "patched_" + file.name;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                return; // Exit after first successful patch
            }
        }
        
        // If no pattern was found
        status.innerText = "Magic bytes pattern not found / Mod may not use Key Manager DRM";
        status.style.color = "#ff4d4d";
    };
    r.readAsArrayBuffer(file);
}

// Attach event listeners to the file input element
document.getElementById("f").onchange = handleFileSelect;
