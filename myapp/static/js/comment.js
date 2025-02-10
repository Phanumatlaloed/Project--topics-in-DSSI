document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll(".add-comment-form").forEach(form => {
        form.addEventListener("submit", function (event) {
            event.preventDefault(); // ❌ หยุด reload หน้า

            let postId = this.dataset.postId;
            let content = this.querySelector("input[name='content']").value;
            let csrfToken = document.querySelector("input[name='csrfmiddlewaretoken']").value;

            if (!content.trim()) {
                alert("❌ Comment cannot be empty!");
                return;
            }

            fetch(`/add_comment/${postId}/`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "X-CSRFToken": csrfToken,
                    "X-Requested-With": "XMLHttpRequest"
                },
                body: new URLSearchParams({ "content": content })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    let commentSection = document.getElementById(`comments-${postId}`);
                    let newComment = document.createElement("div");
                    newComment.classList.add("comment", "border", "p-2", "mb-1", "rounded", "bg-white");
                    newComment.innerHTML = `<b>${data.username}</b>: ${data.content}`;
                    commentSection.appendChild(newComment);

                    form.querySelector("input[name='content']").value = ""; // ✅ เคลียร์ช่อง input
                } else {
                    alert(`❌ Error: ${data.message}`);
                }
            })
            .catch(error => console.error("❌ Error:", error));
        });
    });
});
