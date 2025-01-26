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
    async function sendPostRequest(url, body = null) {
        const headers = {
            "X-CSRFToken": document.querySelector('[name=csrfmiddlewaretoken]').value,
        };
        const options = {
            method: "POST",
            headers: headers,
        };
        if (body) options.body = body;

        try {
            const response = await fetch(url, options);
            if (!response.ok) throw new Error("Network response was not ok");
            return await response.json();
        } catch (error) {
            console.error("Error:", error);
            return { success: false, error: error.message };
        }
    }

    // Handle Comment form for community posts
    document.querySelectorAll(".comment-form").forEach((form) => {
        form.addEventListener("submit", async (e) => {
            e.preventDefault(); // Prevent default form submission behavior

            const formData = new FormData(form);
            const result = await sendPostRequest(form.action, formData);

            if (result.success) {
                const commentSection = form.closest(".post-card").querySelector(".comments-section");
                const newComment = document.createElement("div");
                newComment.className = "comment";
                newComment.innerHTML = `<strong>${result.comment.user}</strong>: ${result.comment.content}`;
                commentSection.appendChild(newComment);
                form.reset();
                showToast("Comment added successfully!");
            } else {
                console.error("Error adding comment:", result.error);
                showToast("Error adding comment.", true);
            }
        });
    });
});
