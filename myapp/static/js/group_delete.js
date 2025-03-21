document.addEventListener("DOMContentLoaded", function () {
    console.log("✅ Comment System & Post Management Loaded!");

    // ===== DELETE POST =====
    document.addEventListener("click", async function (event) {
        const btn = event.target.closest(".delete-btn");
        if (btn) {
            let postId = btn.dataset.postId;
            let groupId = btn.dataset.groupId;

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
                const csrfToken = document.querySelector("[name='csrfmiddlewaretoken']").value;
                
                const response = await fetch(`/community/${groupId}/group/post/${postId}/delete/`, {
                    method: "POST",
                    headers: {
                        "X-CSRFToken": csrfToken,
                        "Content-Type": "application/json"
                    }
                });

                const data = await response.json();

                if (data.success) {
                    alert("โพสต์ถูกลบเรียบร้อยแล้ว!");
                    let postElement = document.getElementById(`post-${postId}`);
                    if (postElement) {
                        postElement.style.opacity = "0";
                        postElement.style.transition = "opacity 0.3s ease";
                        setTimeout(() => postElement.remove(), 300);
                    } else {
                        console.warn(`⚠️ ไม่พบองค์ประกอบที่มี ID: post-${postId}`);
                    }
                } else {
                    alert("เกิดข้อผิดพลาด: " + (data.message || "ไม่สามารถลบโพสต์ได้"));
                }
            }
        }
    });
    
    // Helper function to get CSRF token
    function getCookie(name) {
        let cookieValue = null;
        if (document.cookie && document.cookie !== '') {
            const cookies = document.cookie.split(';');
            for (let i = 0; i < cookies.length; i++) {
                const cookie = cookies[i].trim();
                if (cookie.substring(0, name.length + 1) === (name + '=')) {
                    cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                    break;
                }
            }
        }
        return cookieValue;
    }
});