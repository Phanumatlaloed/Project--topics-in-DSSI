document.addEventListener("DOMContentLoaded", function () {
    const selectedFilesContainer = document.getElementById("selectedEditFiles");

    document.getElementById("editPostImages").addEventListener("change", function () {
        selectedFilesContainer.innerHTML = "";
        for (let i = 0; i < this.files.length; i++) {
            let file = this.files[i];
            let fileName = document.createElement("p");
            fileName.textContent = file.name;
            selectedFilesContainer.appendChild(fileName);
        }
    });

    document.getElementById("editPostVideos").addEventListener("change", function () {
        for (let i = 0; i < this.files.length; i++) {
            let file = this.files[i];
            let fileName = document.createElement("p");
            fileName.textContent = file.name;
            selectedFilesContainer.appendChild(fileName);
        }
    });

    // ✅ ลบไฟล์ที่อัปโหลดแล้ว
    document.querySelectorAll(".remove-existing-file").forEach((button) => {
        button.addEventListener("click", function () {
            const mediaId = this.getAttribute("data-file-id");

            fetch(`/delete_media/${mediaId}/`, {
                method: "DELETE",
                headers: {
                    "X-CSRFToken": getCSRFToken(),
                    "X-Requested-With": "XMLHttpRequest"
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    this.parentElement.remove();
                } else {
                    console.error("❌ Failed to delete:", data.error);
                }
            })
            .catch(error => console.error("❌ AJAX Error:", error));
        });
    });

    function getCSRFToken() {
        return document.querySelector("[name=csrfmiddlewaretoken]").value;
    }
});
