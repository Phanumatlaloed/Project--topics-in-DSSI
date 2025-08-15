document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll(".remove-btn").forEach(button => {
        button.addEventListener("click", function () {
            let postId = this.dataset.postId;
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

            fetch(`/community/${groupId}/group/post/${postId}/unsave/`, {
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