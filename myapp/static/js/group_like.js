document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll(".like-btn").forEach(button => {
        button.addEventListener("click", function () {
            const postId = this.getAttribute("data-post-id");
            const likeCount = document.getElementById(`like-count-${postId}`);
            const csrfToken = getCookie("csrftoken");

            fetch(`/group_post/like/${postId}/like`, {  // ✅ ใช้ URL ที่ถูกต้อง
                method: "POST",
                headers: {
                    "X-CSRFToken": csrfToken,
                    "Content-Type": "application/json"
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    this.innerHTML = data.liked ? "❤️ Unlike" : "🤍 Like";
                    likeCount.innerHTML = `${data.like_count} Likes`;
                }
            })
            .catch(error => console.error("Error:", error));
        });
    });

    // ✅ ฟังก์ชันดึงค่า CSRF Token
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

