document.addEventListener("DOMContentLoaded", () => {
    console.log("✅ Like.js Loaded!");

    document.querySelectorAll(".like-btn").forEach(button => {
        button.addEventListener("click", async (event) => {
            event.preventDefault();
            const postId = button.dataset.postId;
            const likeCountSpan = document.getElementById(`like-count-${postId}`);

            try {
                const response = await fetch(`/like/${postId}/`, {  // ✅ แก้ URL ให้ถูกต้อง
                    method: "POST",
                    headers: {
                        "X-CSRFToken": getCSRFToken(),
                        "X-Requested-With": "XMLHttpRequest"
                    }
                });

                const result = await response.json();
                if (result.success) {
                    button.innerHTML = result.liked ?  "❤️ Unlike" : "🤍 Like";
                    likeCountSpan.textContent = `${result.like_count} Likes`;
                } else {
                    console.error("Error:", result.error);
                }
            } catch (error) {
                console.error("❌ AJAX Error:", error);
            }
        });
    });

    function getCSRFToken() {
        return document.querySelector("[name=csrfmiddlewaretoken]").value;
    }
});
