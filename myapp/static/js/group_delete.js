document.addEventListener("DOMContentLoaded", function () {
    // ✅ ใช้ event delegation เพื่อให้รองรับปุ่มที่โหลดมาภายหลัง
    document.addEventListener("click", function (event) {
        if (event.target.classList.contains("delete-btn")) {
            let postId = event.target.dataset.postId;
            let groupId = event.target.dataset.groupId;

            console.log("🔍 ตรวจสอบค่าที่ได้จากปุ่ม:");
            console.log("📌 postId:", postId);
            console.log("📌 groupId:", groupId);

            if (!postId || postId === "undefined") {
                console.error("❌ postId is undefined. Check if the button has data-post-id.");
                alert("เกิดข้อผิดพลาด: ไม่พบ Post ID");
                return;
            }
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
                .then(response => {
                    if (!response.ok) {
                        throw new Error(`HTTP error! Status: ${response.status}`);
                    }
                    return response.json();
                })
                .then(data => {
                    if (data.success) {
                        alert("โพสต์ถูกลบเรียบร้อยแล้ว!");
                        let postElement = document.getElementById(`post-${postId}`);
                        if (postElement) {
                            postElement.remove();
                        } else {
                            console.warn(`⚠️ ไม่พบองค์ประกอบที่มี ID: post-${postId}`);
                        }
                    } else {
                        alert("เกิดข้อผิดพลาด: " + (data.message || "ไม่สามารถลบโพสต์ได้"));
                    }
                })
                .catch(error => console.error("❌ Error:", error));
            }
        }
    });

    function getCSRFToken() {
        let tokenElement = document.querySelector("[name=csrfmiddlewaretoken]");
        if (!tokenElement) {
            console.error("❌ CSRF token not found in the document.");
            return "";
        }
        return tokenElement.value;
    }
});
