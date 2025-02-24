document.addEventListener("DOMContentLoaded", function () {
    function getCSRFToken() {
        return document.querySelector("[name=csrfmiddlewaretoken]").value;
    }

    document.querySelectorAll(".share-group-btn").forEach(button => {
        button.addEventListener("click", function () {
            const postId = this.getAttribute("data-post-id");
            const groupId = this.getAttribute("data-group-id"); // ✅ ดึง Group ID อัตโนมัติ

            fetch(`/group_post/${postId}/share/`, {
                method: "POST",
                headers: {
                    "X-CSRFToken": getCSRFToken(),
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ group_id: groupId }) // ✅ ส่ง Group ID ไปอัตโนมัติ
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert("✅ แชร์โพสต์ในกลุ่มสำเร็จ!");
                    location.reload(); // ✅ รีโหลดเพื่อแสดงโพสต์ที่แชร์
                } else {
                    alert("❌ ไม่สามารถแชร์โพสต์ได้: " + data.error);
                }
            })
            .catch(error => console.error("Error:", error));
        });
    });
});