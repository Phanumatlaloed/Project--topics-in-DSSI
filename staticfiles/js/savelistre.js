document.addEventListener("DOMContentLoaded", function () {
    // ✅ ปุ่ม "นำออก" สำหรับโพสต์จากหน้าหลัก
    document.querySelectorAll("#homePosts .remove-button").forEach(button => {
        button.addEventListener("click", function () {
            let postId = this.dataset.postId;
            let postItem = this.closest(".post-item");
            
            console.log("กำลังลบโพสต์หน้าหลัก ID:", postId); // เพิ่มเพื่อดีบัก
            
            // สร้าง CSRF token
            const csrftoken = getCSRFToken();
            
            fetch(`/remove_saved_post/${postId}/`, {
                method: "POST",
                headers: {
                    "X-CSRFToken": csrftoken,
                    "X-Requested-With": "XMLHttpRequest",
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({})
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // ลบโพสต์จาก DOM
                    postItem.remove();
                    
                    // ตรวจสอบว่ายังมีโพสต์เหลืออยู่หรือไม่
                    const remainingPosts = document.querySelectorAll('#homePosts .post-item');
                    
                    // ถ้าไม่มีโพสต์เหลือแล้ว แสดงข้อความว่าไม่มีรายการ
                    if (remainingPosts.length === 0) {
                        const emptyState = document.createElement('div');
                        emptyState.className = 'empty-state';
                        emptyState.innerHTML = `
                            <i class="fas fa-bookmark-slash"></i>
                            <p>ยังไม่มีโพสต์ที่บันทึกไว้จากหน้าหลัก</p>
                        `;
                        
                        document.querySelector('#homePosts .post-container').appendChild(emptyState);
                    }
                } else {
                    alert("❌ ไม่สามารถลบโพสต์นี้ได้");
                }
            })
            .catch(error => {
                console.error("❌ Error:", error);
                alert("เกิดข้อผิดพลาดในการลบโพสต์ กรุณาลองใหม่อีกครั้ง");
            });
        });
    });

    // ✅ ปุ่ม "นำออก" สำหรับโพสต์จากชุมชน
    document.querySelectorAll("#groupPosts .remove-button").forEach(button => {
        button.addEventListener("click", function () {
            let postId = this.dataset.postId;
            let groupId = this.dataset.groupId;
            let postItem = this.closest(".post-item");
            
            console.log("กำลังลบโพสต์ชุมชน ID:", postId, "Group ID:", groupId); // เพิ่มเพื่อดีบัก
            
            // สร้าง CSRF token
            const csrftoken = getCSRFToken();
            
            fetch(`/community/${groupId}/group/post/${postId}/unsave/`, {
                method: "POST",
                headers: {
                    "X-CSRFToken": csrftoken,
                    "X-Requested-With": "XMLHttpRequest",
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    group_id: groupId
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // ลบโพสต์จาก DOM
                    postItem.remove();
                    
                    // ตรวจสอบว่ายังมีโพสต์เหลืออยู่หรือไม่
                    const remainingPosts = document.querySelectorAll('#groupPosts .post-item');
                    
                    // ถ้าไม่มีโพสต์เหลือแล้ว แสดงข้อความว่าไม่มีรายการ
                    if (remainingPosts.length === 0) {
                        const emptyState = document.createElement('div');
                        emptyState.className = 'empty-state';
                        emptyState.innerHTML = `
                            <i class="fas fa-users-slash"></i>
                            <p>ยังไม่มีโพสต์ที่บันทึกไว้จากชุมชน</p>
                        `;
                        
                        document.querySelector('#groupPosts .post-container').appendChild(emptyState);
                    }
                } else {
                    alert("❌ ไม่สามารถลบโพสต์นี้ได้");
                }
            })
            .catch(error => {
                console.error("❌ Error:", error);
                alert("เกิดข้อผิดพลาดในการลบโพสต์ กรุณาลองใหม่อีกครั้ง");
            });
        });
    });

    // ✅ ฟังก์ชันดึง CSRF Token
    function getCSRFToken() {
        // วิธีที่ 1: หา CSRF token จาก input hidden ในฟอร์ม
        let csrfToken = document.querySelector("input[name='csrfmiddlewaretoken']");
        if (csrfToken) return csrfToken.value;
        
        // วิธีที่ 2: หา CSRF token จาก cookies
        let cookieValue = null;
        if (document.cookie) {
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