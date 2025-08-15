document.addEventListener("DOMContentLoaded", function () {
    console.log("✅ Save Post System Loaded!");
    
    // ✅ ปุ่ม Save / Unsave
    document.querySelectorAll(".save-btn").forEach(button => {
        button.addEventListener("click", function () {
            let postId = this.dataset.postId;
            let groupId = this.dataset.groupId;  // รับค่า group_id จากปุ่มหรือ HTML element
            let btn = this;
            
            if (!postId || postId === "undefined") {
                console.error("❌ postId is undefined");
                return;
            }
            
            if (!groupId || groupId === "undefined") {
                console.error("❌ groupId is undefined");
                return;
            }
            
            console.log(`📌 Saving post: ${postId} in group: ${groupId}`);

            fetch(`/community/${groupId}/group/post/${postId}/save/`, { 
                method: "POST",
                headers: {
                    "X-CSRFToken": getCSRFToken(),
                    "Content-Type": "application/json"
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.success && data.saved === true) {
                    btn.innerHTML = '<i class="fas fa-bookmark"></i> ยกเลิกบันทึก';
                } else if (data.success && data.saved === false) {
                    btn.innerHTML = '<i class="far fa-bookmark"></i> บันทึก';
                } else {
                    alert("❌ ไม่สามารถบันทึกโพสต์ได้");
                }
            })                
            .catch(error => {
                console.error("❌ Error:", error);
                alert("❌ เกิดข้อผิดพลาดในการบันทึกโพสต์");
            });
        });
    });

    function getCSRFToken() {
        let csrfToken = document.querySelector("input[name='csrfmiddlewaretoken']");
        if (csrfToken) {
            return csrfToken.value;
        }
        
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
});