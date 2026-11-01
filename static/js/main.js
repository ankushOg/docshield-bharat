// DocShield Client-Side Validation & Upload UI (static/js/main.js)

document.addEventListener("DOMContentLoaded", function () {
    const fileInput = document.getElementById("documentInput");
    const dropZone = document.getElementById("dropZone");
    const previewInfo = document.getElementById("filePreviewInfo");
    const uploadForm = document.getElementById("uploadForm");
    const submitBtn = document.getElementById("scanSubmitBtn");
    const spinner = document.getElementById("processingSpinner");

    const allowedExtensions = ["pdf", "jpg", "jpeg", "png"];
    const maxBytes = 10 * 1024 * 1024; // 10 MB

    if (fileInput && previewInfo) {
        fileInput.addEventListener("change", function () {
            const file = fileInput.files[0];
            if (!file) {
                previewInfo.classList.add("d-none");
                return;
            }
            const ext = file.name.split(".").pop().toLowerCase();
            if (!allowedExtensions.includes(ext)) {
                alert("Unsupported file format! Please select a PDF, JPG, JPEG, or PNG document.");
                fileInput.value = "";
                previewInfo.classList.add("d-none");
                return;
            }
            if (file.size > maxBytes) {
                alert("File exceeds the 10 MB limit! Please choose a smaller document.");
                fileInput.value = "";
                previewInfo.classList.add("d-none");
                return;
            }
            const sizeKB = (file.size / 1024).toFixed(1);
            previewInfo.textContent = `Selected: ${file.name} (${sizeKB} KB)`;
            previewInfo.classList.remove("d-none");
        });
    }

    if (dropZone) {
        ["dragenter", "dragover"].forEach((evt) => {
            dropZone.addEventListener(evt, (e) => {
                e.preventDefault();
                dropZone.classList.add("dragover");
            });
        });
        ["dragleave", "drop"].forEach((evt) => {
            dropZone.addEventListener(evt, () => {
                dropZone.classList.remove("dragover");
            });
        });
    }

    if (uploadForm && submitBtn && spinner) {
        uploadForm.addEventListener("submit", function () {
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Scanning Document...';
            spinner.classList.remove("d-none");
        });
    }
});
