document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll(".delete-btn").forEach(button => {
        button.addEventListener("click", function () {
            let postId = this.dataset.postId;
            let groupId = this.dataset.groupId; // ✅ ดึง groupId จากปุ่ม Delete

            if (!groupId || groupId === "undefined") {
                console.error("❌ groupId is undefined. Check if the button has data-group-id.");
                alert("เกิดข้อผิดพลาด: ไม่พบ Group ID");
                return;
            }

            if (confirm("คุณต้องการลบโพสต์ใช่หรือไม่ ?")) {
                fetch(`/community/${groupId}/group/post/${postId}/delete/`, {
                    method: "POST",
                    headers: {
                        "X-CSRFToken": getCSRFToken(),
                        "Content-Type": "application/json"
                    }
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        alert("โพสต์ถูกลบเรียบร้อยแล้ว!");
                        document.getElementById(`post-${postId}`).remove();
                    } else {
                        alert("เกิดข้อผิดพลาด: " + data.message);
                    }
                })
                .catch(error => console.error("Error:", error));
            }
        });
    });

    function getCSRFToken() {
        return document.querySelector("[name=csrfmiddlewaretoken]").value;
    }
});
