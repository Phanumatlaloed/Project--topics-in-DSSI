document.addEventListener("DOMContentLoaded", () => {
    const removeForms = document.querySelectorAll(".remove-post-form");
    const toast = document.getElementById("toast");

    removeForms.forEach((form) => {
        form.addEventListener("submit", async (event) => {
            event.preventDefault();

            const postId = form.action.split("/").slice(-2, -1)[0]; // ดึง post_id จาก URL
            const response = await fetch(form.action, {
                method: "POST",
                headers: {
                    "X-CSRFToken": form.querySelector("[name=csrfmiddlewaretoken]").value,
                },
            });

            const result = await response.json();
            if (response.ok) {
                // ลบโพสต์จาก DOM
                const postElement = document.getElementById(`post-${postId}`);
                if (postElement) {
                    postElement.remove();
                }

                // แสดงข้อความแจ้งเตือน
                showToast(result.message, true);
            } else {
                showToast(result.message, false);
            }
        });
    });

    function showToast(message, success) {
        toast.textContent = message;
        toast.className = success ? "toast show success" : "toast show error";

        setTimeout(() => {
            toast.className = "toast";
        }, 3000);
    }
});
