document.addEventListener("DOMContentLoaded", function () {
    console.log("✅ Comment System Loaded!");

    // ===== ADD COMMENT =====
    document.querySelectorAll(".add-comment-form").forEach(form => {
        form.addEventListener("submit", async function (e) {
            e.preventDefault();
            const postId = form.dataset.postId;
            const contentInput = form.querySelector("input[name='content']");
            const content = contentInput.value.trim();
            const csrfToken = document.querySelector("[name='csrfmiddlewaretoken']").value;

            if (!content) return;

            const response = await fetch(`/group_post/${postId}/add_comment/`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRFToken": csrfToken
                },
                body: JSON.stringify({ content })
            });

            const data = await response.json();

            if (data.success) {
                const commentsList = document.getElementById(`comments-${postId}`);
                const newComment = document.createElement("div");
                newComment.className = "comment";
                newComment.id = `comment-${data.comment_id}`;
                newComment.setAttribute("data-comment-id", data.comment_id);  // ✅ กำหนดค่า data-comment-id

                newComment.innerHTML = `
                    <div class="d-flex justify-content-between">
                        <div><b>${data.comment.user}</b>: <span class="comment-content">${data.comment.content}</span></div>
                        <div class="dropdown">
                            <button class="btn btn-sm btn-light dropdown-toggle" type="button" data-bs-toggle="dropdown">
                                <i class="fas fa-ellipsis-v"></i>
                            </button>
                            <ul class="dropdown-menu">
                                <li><button class="dropdown-item edit-comment-btn" data-comment-id="${data.comment_id}">
                                    <i class="fas fa-edit"></i> Edit
                                </button></li>
                                <li><button class="dropdown-item delete-comment-btn" data-comment-id="${data.comment_id}">
                                    <i class="fas fa-trash-alt"></i> Delete
                                </button></li>
                            </ul>
                        </div>
                    </div>
                `;
                commentsList.appendChild(newComment);
                contentInput.value = "";

                console.log("✅ คอมเมนต์ถูกเพิ่ม: ", data.comment_id);
            } else {
                alert(data.message);
            }
        });
    });

    // ===== DELETE COMMENT =====
    document.addEventListener("click", async function (event) {
        const btn = event.target.closest(".delete-comment-btn");
        if (btn) {
            const commentId = btn.dataset.commentId;
            if (!commentId || commentId === "undefined") {
                console.error("❌ ไม่พบ Comment ID");
                alert("เกิดข้อผิดพลาด: ไม่พบ Comment ID");
                return;
            }

            if (confirm("คุณต้องการลบคอมเมนต์นี้ใช่ไหม?")) {
                const csrfToken = document.querySelector("[name='csrfmiddlewaretoken']").value;

                const response = await fetch(`/group_comment/${commentId}/delete/`, {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "X-CSRFToken": csrfToken
                    }
                });

                const data = await response.json();
                if (data.success) {
                    const commentEl = document.getElementById(`comment-${commentId}`);
                    if (commentEl) {
                        commentEl.style.opacity = "0";
                        commentEl.style.transition = "opacity 0.3s ease";
                        setTimeout(() => commentEl.remove(), 300);
                    }
                } else {
                    alert(data.message);
                }
            }
        }
    });

    // ===== EDIT COMMENT =====
    document.addEventListener("click", async function (event) {
        const btn = event.target.closest(".edit-comment-btn");
        if (btn) {
            const commentId = btn.dataset.commentId;
            if (!commentId || commentId === "undefined") {
                console.error("❌ ไม่พบ Comment ID");
                alert("เกิดข้อผิดพลาด: ไม่พบ Comment ID");
                return;
            }

            const commentEl = document.getElementById(`comment-${commentId}`);
            const contentSpan = commentEl.querySelector(".comment-content");
            const originalContent = contentSpan.textContent;

            const newContent = prompt("แก้ไขคอมเมนต์", originalContent);
            if (newContent !== null && newContent.trim() !== originalContent.trim()) {
                const csrfToken = document.querySelector("[name='csrfmiddlewaretoken']").value;

                const response = await fetch(`/group_comment/${commentId}/edit/`, {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "X-CSRFToken": csrfToken
                    },
                    body: JSON.stringify({ content: newContent })
                });

                const data = await response.json();
                if (data.success) {
                    contentSpan.textContent = newContent;
                } else {
                    alert(data.message);
                }
            }
        }
    });
});
