document.addEventListener("DOMContentLoaded", function () {
    // ✅ ดึง CSRF Token จากคุกกี้
    function getCSRFToken() {
        let cookieValue = null;
        if (document.cookie && document.cookie !== '') {
            const cookies = document.cookie.split(';');
            for (let i = 0; i < cookies.length; i++) {
                const cookie = cookies[i].trim();
                if (cookie.startsWith('csrftoken=')) {
                    cookieValue = cookie.substring(10);
                    break;
                }
            }
        }
        return cookieValue;
    }

    document.addEventListener("DOMContentLoaded", function () {
        const postForm = document.getElementById("postForm");
        
        if (postForm) {
            postForm.addEventListener("submit", function (e) {
                e.preventDefault();
    
                const formData = new FormData(postForm);
                fetch(postForm.action, {
                    method: "POST",
                    body: formData,
                    headers: { "X-CSRFToken": document.querySelector("[name=csrfmiddlewaretoken]").value },
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        window.location.reload();  // ✅ รีเฟรชหน้าเพื่อแสดงโพสต์ใหม่
                    } else {
                        alert("โพสต์ไม่สำเร็จ: " + data.message);
                    }
                })
                .catch(error => console.error("Error:", error));
            });
        }
    });
});