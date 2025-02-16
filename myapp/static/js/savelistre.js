document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll(".remove-btn").forEach(button => {
        button.addEventListener("click", function () {
            let postId = this.dataset.postId;
            let groupId = this.dataset.groupId;  // groupId สำหรับโพสต์ในกลุ่ม
            let card = this.closest(".post-item");

            // ✅ ดึง CSRF Token จาก Cookie
            function getCSRFToken() {
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

            // ตรวจสอบว่าโพสต์เป็นของกลุ่มหรือไม่
            let url = groupId ? 
                      `/community/${groupId}/group/post/${postId}/delete/` :  // ถ้าเป็นโพสต์ในกลุ่ม
                      `/remove_saved_post/${postId}/`;  // ถ้าเป็นโพสต์ในหน้า Home

            fetch(url, {
                method: "POST",
                headers: {
                    "X-CSRFToken": getCSRFToken(),
                    "Content-Type": "application/json"
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    card.remove();
                } else {
                    alert("❌ Error: " + data.message);
                }
            })
            .catch(error => console.error("Fetch error:", error));
        });
    });
});
