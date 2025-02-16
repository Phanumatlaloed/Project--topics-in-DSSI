document.querySelectorAll(".edit-btn").forEach(button => {
    button.addEventListener("click", function () {
        let postId = this.getAttribute("data-post-id");
        let newContent = prompt("กรุณาแก้ไขข้อความ:", "");

        if (newContent !== null && newContent.trim() !== "") {
            fetch(`/group/post/${postId}/edit/`, {
                method: "POST", // ✅ ใช้ POST (เดิมอาจเป็น GET)
                headers: {
                    "X-CSRFToken": getCSRFToken(),
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ content: newContent }) // ✅ ส่งข้อมูลใหม่
            })
            .then(response => response.json())
            .then(data => {
                alert(data.message);
                if (data.success) {
                    document.getElementById(`post-${postId}`).querySelector(".post-content").textContent = newContent;
                }
            });
        }
    });
});
