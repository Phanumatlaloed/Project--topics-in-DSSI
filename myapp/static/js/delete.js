document.addEventListener("DOMContentLoaded", function() {
    document.querySelectorAll(".delete-btn").forEach(button => {
        button.addEventListener("click", function() {
            let postId = this.dataset.postId;
            let postElement = document.getElementById(`post-${postId}`);

            if (!confirm("คุณแน่ใจหรือไม่ว่าต้องการลบโพสต์นี้?")) return;

            // ✅ ปิดการใช้งานปุ่มลบหลังจากคลิก
            this.disabled = true;

            fetch(`/post/${postId}/delete/`, {
                method: "POST",
                headers: {
                    "X-CSRFToken": getCSRFToken(),
                    "X-Requested-With": "XMLHttpRequest"
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    postElement.remove();  // ✅ ลบโพสต์ออกจาก DOM
                    alert("✅ โพสต์ถูกลบเรียบร้อยแล้ว!");
                } else {
                    alert(`❌ เกิดข้อผิดพลาด: ${data.message}`);
                    this.disabled = false;  // ✅ เปิดใช้งานปุ่มอีกครั้งหากลบไม่สำเร็จ
                }
            })
            .catch(error => {
                console.error("❌ Error:", error);
                this.disabled = false;
            });
        });
    });
});
