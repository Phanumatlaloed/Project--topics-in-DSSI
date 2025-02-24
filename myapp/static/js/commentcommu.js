document.addEventListener("DOMContentLoaded", function () {
    function getCSRFToken() {
        return document.querySelector("[name=csrfmiddlewaretoken]").value;
    }

    // ✅ ฟังก์ชันเพิ่มคอมเมนต์
    document.querySelectorAll(".add-comment-form").forEach(form => {
        form.addEventListener("submit", function (event) {
            event.preventDefault(); // ป้องกันรีเฟรชหน้า

            let postId = this.dataset.postId;
            let content = this.querySelector("input[name='content']").value;

            if (!content.trim()) {
                alert("⚠️ กรุณากรอกข้อความก่อนส่งคอมเมนต์!");
                return;
            }

            fetch(`/group_post/comment/${postId}/`, {  // ✅ แก้ URL ให้ตรงกับ Django
                method: "POST",
                headers: {
                    "X-CSRFToken": getCSRFToken(),
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ content: content })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    let commentSection = document.getElementById(`comments-${postId}`);
                    let newComment = document.createElement("div");
                    newComment.className = "comment border p-2 mb-1 rounded bg-white";
                    newComment.innerHTML = `<b>${data.comment.user}</b>: ${data.comment.content}`;
                    commentSection.appendChild(newComment);
                    
                    // ✅ เคลียร์ฟอร์มหลังจากโพสต์สำเร็จ
                    form.querySelector("input[name='content']").value = "";
                } else {
                    alert(data.message);
                }
            })
            .catch(error => console.error("Error:", error));
        });
    });
});