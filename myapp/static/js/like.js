document.addEventListener("DOMContentLoaded", function () {
    const toast = document.getElementById("toast");

    // Function to show Toast Notification
    function showToast(message, isError = false) {
        if (toast) {
            toast.textContent = message;
            toast.className = isError ? "show error" : "show success";
            setTimeout(() => {
                toast.className = toast.className.replace("show", "").trim();
            }, 3000);
        }
    }

    // Function to send POST request
    async function sendPostRequest(url) {
        const headers = {
            "X-CSRFToken": document.querySelector('[name=csrfmiddlewaretoken]').value,
        };

        try {
            const response = await fetch(url, {
                method: "POST",
                headers: headers,
            });
            if (!response.ok) throw new Error("Network response was not ok");
            return await response.json();
        } catch (error) {
            console.error("Error:", error);
            return { success: false, error: error.message };
        }
    }

    // Handle Like button for posts
    document.querySelectorAll(".like-btn").forEach((button) => {
        button.addEventListener("click", async (e) => {
            e.preventDefault(); // Prevent form submission
            const form = button.closest("form");
            const result = await sendPostRequest(form.action);

            if (result.success) {
                const likeCount = button.nextElementSibling;
                likeCount.textContent = `${result.like_count} Likes`;
                button.textContent = result.liked ? "❤️ Unlike" : "🤍 Like";
                showToast(result.liked ? "You liked the post!" : "You unliked the post!");
            } else {
                console.error("Error toggling like:", result.error);
                showToast("Error toggling like.", true);
            }
        });
    });
});
