document.addEventListener("DOMContentLoaded", function () {
    const fileInput = document.getElementById("editPostImages");
    const fileVideoInput = document.getElementById("editPostVideos");
    const selectedFilesContainer = document.getElementById("selectedEditFiles");

    fileInput.addEventListener("change", function () {
        selectedFilesContainer.innerHTML = ""; // ล้างรายการไฟล์ที่เลือก

        for (let i = 0; i < fileInput.files.length; i++) {
            let file = fileInput.files[i];
            let fileName = document.createElement("p");
            fileName.textContent = file.name;
            selectedFilesContainer.appendChild(fileName);
        }
    });

    fileVideoInput.addEventListener("change", function () {
        for (let i = 0; i < fileVideoInput.files.length; i++) {
            let file = fileVideoInput.files[i];
            let fileName = document.createElement("p");
            fileName.textContent = file.name;
            selectedFilesContainer.appendChild(fileName);
        }
    });

    // ✅ ลบไฟล์ที่อัปโหลดแล้ว
    document.querySelectorAll(".remove-existing-file").forEach((button) => {
        button.addEventListener("click", function () {
            const mediaId = this.getAttribute("data-file-id");
            fetch(`/delete_media/${mediaId}/`, { method: "DELETE" })
                .then((response) => response.json())
                .then((data) => {
                    if (data.success) {
                        this.parentElement.remove();
                    }
                });
        });
    });
});
