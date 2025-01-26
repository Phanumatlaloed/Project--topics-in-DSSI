document.addEventListener("DOMContentLoaded", function () {
    const commentForms = document.querySelectorAll(".comment-form");
    
    commentForms.forEach((form) => {
        form.addEventListener("submit", async (event) => {
            event.preventDefault();

            const formData = new FormData(form);
            const response = await fetch(form.action, {
                method: "POST",
                body: formData,
                headers: {
                    "X-CSRFToken": form.querySelector("[name=csrfmiddlewaretoken]").value,
                },
            });

            if (response.ok) {
                const result = await response.json();
                if (result.success) {
                    alert("Comment added successfully!");
                    window.location.reload();
                } else {
                    alert("Failed to add comment.");
                }
            } else {
                alert("Error occurred while adding comment.");
            }
        });
    });
});
