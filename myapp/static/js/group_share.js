document.addEventListener("DOMContentLoaded", function () {
    console.log("✅ Share Post System Loaded!");
    
    function getCSRFToken() {
        // Try to get from element
        let csrfInput = document.querySelector("[name=csrfmiddlewaretoken]");
        if (csrfInput) return csrfInput.value;
        
        // Fallback to cookie
        let cookieValue = null;
        if (document.cookie && document.cookie !== '') {
            let cookies = document.cookie.split(';');
            for (let i = 0; i < cookies.length; i++) {
                let cookie = cookies[i].trim();
                if (cookie.startsWith("csrftoken=")) {
                    cookieValue = cookie.substring("csrftoken=".length, cookie.length);
                    break;
                }
            }
        }
        return cookieValue;
    }

    // กรณีปุ่มแชร์โพสต์ในกลุ่ม (share-btn)
    document.querySelectorAll(".share-btn").forEach(button => {
        button.addEventListener("click", function () {
            const postId = this.getAttribute("data-post-id");
            const groupId = this.getAttribute("data-group-id");

            if (!postId || !groupId) {
                console.error("❌ ข้อมูลไม่ครบถ้วน:", { postId, groupId });
                alert("❌ ไม่สามารถแชร์โพสต์ได้: ข้อมูลไม่ครบถ้วน");
                return;
            }

            fetch(`/community/${groupId}/group/post/${postId}/share/`, {
                method: "POST",
                headers: {
                    "X-CSRFToken": getCSRFToken(),
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ group_id: groupId })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert("✅ แชร์โพสต์ในกลุ่มสำเร็จ!");
                } else {
                    alert("❌ ไม่สามารถแชร์โพสต์ได้: " + (data.error || "เกิดข้อผิดพลาด"));
                }
            })
            .catch(error => {
                console.error("Error:", error);
                alert("❌ เกิดข้อผิดพลาดในการแชร์โพสต์");
            });
        });
    });

    // กรณีปุ่มแชร์โพสต์จากกลุ่มไปกลุ่ม (share-group-btn) 
    document.querySelectorAll(".share-group-btn").forEach(button => {
        button.addEventListener("click", function () {
            const postId = this.getAttribute("data-post-id");
            const groupId = this.getAttribute("data-group-id");

            if (!postId || !groupId) {
                console.error("❌ ข้อมูลไม่ครบถ้วน:", { postId, groupId });
                alert("❌ ไม่สามารถแชร์โพสต์ได้: ข้อมูลไม่ครบถ้วน");
                return;
            }

            fetch(`/group_post/${postId}/share/`, {
                method: "POST",
                headers: {
                    "X-CSRFToken": getCSRFToken(),
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ group_id: groupId })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert("✅ แชร์โพสต์ในกลุ่มสำเร็จ!");
                    location.reload(); // รีโหลดเพื่อแสดงโพสต์ที่แชร์
                } else {
                    alert("❌ ไม่สามารถแชร์โพสต์ได้: " + (data.error || "เกิดข้อผิดพลาด"));
                }
            })
            .catch(error => {
                console.error("Error:", error);
                alert("❌ เกิดข้อผิดพลาดในการแชร์โพสต์");
            });
        });
    });
});