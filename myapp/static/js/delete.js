document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll(".delete-form").forEach(form => {
        form.addEventListener("submit", function (event) {
            event.preventDefault();
            const postId = this.getAttribute("data-post-id");

            if (confirm("คุณต้องการลบโพสต์นี้ใช่หรือไม่?")) {
                fetch(`/post/${postId}/delete/`, {
                    method: "POST",
                    headers: {
                        "X-CSRFToken": document.querySelector("[name=csrfmiddlewaretoken]").value,
                        "X-Requested-With": "XMLHttpRequest"
                    }
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        alert("✅ โพสต์ถูกลบแล้ว!");
                        document.getElementById(`post-${postId}`).remove();
                    } else {
                        alert("❌ ลบโพสต์ไม่สำเร็จ: " + data.message);
                    }
                })
                .catch(error => console.error("Error:", error));
            }
        });
    });
});
