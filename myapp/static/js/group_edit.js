document.addEventListener("DOMContentLoaded", function () {
    console.log("✅ group_edit.js Loaded!");

    function getCSRFToken() {
        return document.querySelector("[name=csrfmiddlewaretoken]").value;
    }

    document.querySelectorAll(".remove-existing-file").forEach((button) => {
        button.addEventListener("click", function () {
            const mediaId = this.getAttribute("data-file-id");
            console.log(`📌 Trying to delete media ID: ${mediaId}`);

            fetch(`/delete_media/${mediaId}/`, {
                method: "DELETE",
                headers: {
                    "X-CSRFToken": getCSRFToken(),
                    "X-Requested-With": "XMLHttpRequest",
                },
            })
                .then((response) => response.json())
                .then((data) => {
                    if (data.success) {
                        console.log("✅ Media deleted successfully:", mediaId);
                        this.parentElement.remove();
                    } else {
                        console.error("❌ Error deleting media:", data.error);
                    }
                })
                .catch((error) => console.error("❌ AJAX Error:", error));
        });
    });
});
