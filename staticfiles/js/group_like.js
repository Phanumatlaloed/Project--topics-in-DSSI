document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll(".like-btn").forEach(button => {
        button.addEventListener("click", function () {
            const postId = this.getAttribute("data-post-id");
            const likeCount = document.getElementById(`like-count-${postId}`);
            const csrfToken = getCookie("csrftoken");
            
            // ตรวจสอบว่ามี likeCount หรือไม่
            if (!postId || !likeCount) {
                console.error("ไม่พบ postId หรือ likeCount element");
                return;
            }
            
            fetch(`/group_post/like/${postId}/like`, {
                method: "POST",
                headers: {
                    "X-CSRFToken": csrfToken,
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
                    // อัพเดทปุ่มตามสถานะการถูกใจ
                    const icon = document.createElement('i');
                    
                    // ล้างเนื้อหาปุ่มเดิม
                    button.innerHTML = '';
                    
                    if (data.liked) {
                        icon.className = 'fas fa-heart';
                        button.appendChild(icon);
                        button.appendChild(document.createTextNode(' ถูกใจแล้ว'));
                        button.classList.add('liked');
                    } else {
                        icon.className = 'far fa-heart';
                        button.appendChild(icon);
                        button.appendChild(document.createTextNode(' ถูกใจ'));
                        button.classList.remove('liked');
                    }
                    
                    // อัพเดทจำนวนคนถูกใจ
                    likeCount.textContent = `${data.like_count} ถูกใจ`;
                } else {
                    console.error("เกิดข้อผิดพลาด:", data.error || "ไม่พบข้อความแสดงความผิดพลาด");
                }
            })
            .catch(error => {
                console.error("เกิดข้อผิดพลาดในการส่งคำขอ:", error);
            });
        });
    });
    
    // ฟังก์ชันดึงค่า CSRF Token
    function getCookie(name) {
        let cookieValue = null;
        if (document.cookie && document.cookie !== "") {
            const cookies = document.cookie.split(";");
            for (let i = 0; i < cookies.length; i++) {
                const cookie = cookies[i].trim();
                if (cookie.startsWith(name + "=")) {
                    cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                    break;
                }
            }
        }
        return cookieValue;
    }
});