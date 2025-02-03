document.addEventListener("DOMContentLoaded", () => {
    const postMedia = document.getElementById("postMedia");
    const selectedFiles = document.getElementById("selectedFiles");

    function updateSelectedFiles() {
        selectedFiles.innerHTML = "";

        // ✅ ตรวจสอบว่ามีไฟล์ถูกเลือกไหม
        if (postMedia.files.length === 0) {
            console.warn("🚨 No files selected!");
        }

        [...postMedia.files].forEach(file => {
            const item = document.createElement("p");
            item.textContent = file.type.startsWith("image") ? `🖼️ ${file.name}` : `🎥 ${file.name}`;
            selectedFiles.appendChild(item);
        });
    }

    postMedia.addEventListener("change", updateSelectedFiles);
});
