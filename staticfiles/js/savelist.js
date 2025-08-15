document.addEventListener("DOMContentLoaded", function () {
    // ✅ ปุ่ม Save / Unsave
    document.querySelectorAll(".save-btn").forEach(button => {
        button.addEventListener("click", function () {
            let postId = this.dataset.postId;
            let btn = this;
            
            fetch(`/save/${postId}/`, {
                method: "POST",
                headers: {
                    "X-CSRFToken": getCSRFToken(),
                    "X-Requested-With": "XMLHttpRequest",
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({})
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // สร้างไอคอนใหม่
                    let icon = document.createElement('i');
                    
                    // ล้างเนื้อหาปุ่มเดิม
                    btn.innerHTML = '';
                    
                    if (data.saved) {
                        // กรณีบันทึกแล้ว
                        icon.className = 'fas fa-bookmark';
                        btn.appendChild(icon);
                        btn.appendChild(document.createTextNode(' ยกเลิกบันทึก'));
                        btn.classList.add("btn-success");
                        btn.classList.remove("btn-light");
                        btn.dataset.saved = "true";
                    } else {
                        // กรณียังไม่บันทึก
                        icon.className = 'far fa-bookmark';
                        btn.appendChild(icon);
                        btn.appendChild(document.createTextNode(' บันทึก'));
                        btn.classList.add("btn-light");
                        btn.classList.remove("btn-success");
                        btn.dataset.saved = "false";
                    }
                } else {
                    alert("❌ ไม่สามารถบันทึกโพสต์ได้");
                }
            })
            .catch(error => console.error("❌ Error:", error));
        });
    });

    // ✅ ปุ่ม Remove บน Saved List
    document.querySelectorAll(".remove-btn").forEach(button => {
        button.addEventListener("click", function () {
            let postId = this.dataset.postId;
            let card = this.closest(".col-md-6, .col-lg-4");
            
            fetch(`/remove_saved_post/${postId}/`, {
                method: "POST",
                headers: {
                    "X-CSRFToken": getCSRFToken(),
                    "X-Requested-With": "XMLHttpRequest",
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({})
            })
            .then(response => response.json())
            .then(data => {
                if (data.success && !data.saved) {
                    card.remove();  // ✅ ลบโพสต์ออกจาก Saved List
                } else {
                    alert("❌ ไม่สามารถลบโพสต์นี้ได้");
                }
            })
            .catch(error => console.error("❌ Error:", error));
        });
    });

    // ✅ ฟังก์ชันดึง CSRF Token
    function getCSRFToken() {
        let csrfToken = document.querySelector("input[name='csrfmiddlewaretoken']");
        if (csrfToken) return csrfToken.value;
        
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