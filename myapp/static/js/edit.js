document.addEventListener("DOMContentLoaded", function () {
    // ✅ ฟังก์ชันลบไฟล์ที่อัปโหลดไว้แล้ว
    document.querySelectorAll(".remove-existing-file").forEach(button => {
        button.addEventListener("click", function () {
            const mediaId = this.dataset.fileId;

            if (!mediaId || mediaId === "undefined") {
                console.error("❌ Error: mediaId is undefined!");
                return;
            }

            fetch(`/delete_media/${mediaId}/`, {
                method: "DELETE",
                headers: {
                    "Content-Type": "application/json"
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    this.closest(".file-item").remove(); // ✅ ลบไฟล์จาก UI
                } else {
                    console.error("ลบไม่สำเร็จ:", data.message);
                }
            })
            .catch(error => console.error("เกิดข้อผิดพลาด:", error));
        });
    });
});
