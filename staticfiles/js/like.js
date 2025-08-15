document.addEventListener("DOMContentLoaded", () => {
    console.log("✅ โหลดไฟล์ Like.js เรียบร้อยแล้ว!");
    
    // เลือกปุ่มถูกใจทั้งหมดในหน้าเว็บ
    document.querySelectorAll(".like-btn").forEach(button => {
        button.addEventListener("click", async (event) => {
            event.preventDefault();
            const postId = button.dataset.postId;
            const likeCountSpan = document.getElementById(`like-count-${postId}`);
            
            if (!postId || !likeCountSpan) {
                console.error("ไม่พบ postId หรือ likeCountSpan");
                return;
            }
            
            try {
                const response = await fetch(`/like/${postId}/`, {
                    method: "POST",
                    headers: {
                        "X-CSRFToken": getCSRFToken(),
                        "X-Requested-With": "XMLHttpRequest"
                    }
                });
                
                const result = await response.json();
                if (result.success) {
                    // สร้างไอคอนแยกจาก text เพื่อป้องกันปัญหา
                    const icon = document.createElement('i');
                    button.innerHTML = '';
                    
                    // อัพเดทปุ่มตามสถานะการถูกใจ
                    if (result.liked) {
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
                    likeCountSpan.textContent = `${result.like_count} ถูกใจ`;
                } else {
                    console.error("เกิดข้อผิดพลาด:", result.error);
                }
            } catch (error) {
                console.error("❌ เกิดข้อผิดพลาด AJAX:", error);
            }
        });
    });
    
    function getCSRFToken() {
        const tokenInput = document.querySelector("[name=csrfmiddlewaretoken]");
        if (!tokenInput) {
            console.error("ไม่พบ CSRF token");
            return '';
        }
        return tokenInput.value;
    }
});