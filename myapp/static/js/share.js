document.addEventListener("DOMContentLoaded", function () {
    const shareButtons = document.querySelectorAll(".share-btn");

    shareButtons.forEach(button => {
        button.addEventListener("click", function () {
            const postId = this.getAttribute("data-post-id");

            fetch(`/post/${postId}/share/`, {
                method: "POST",
                headers: {
                    "X-CSRFToken": getCSRFToken(),
                    "X-Requested-With": "XMLHttpRequest"
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert("✅ แชร์โพสต์เรียบร้อยแล้ว!");
                    location.reload(); // ✅ รีโหลดหน้าเพื่อแสดงโพสต์ที่แชร์
                } else {
                    alert("❌ เกิดข้อผิดพลาด: " + data.message);
                }
            })
            .catch(error => {
                console.error("Error:", error);
                alert("❌ ไม่สามารถแชร์โพสต์ได้");
            });
        });
    });

    // ✅ ฟังก์ชันดึงค่า CSRF Token
    function getCSRFToken() {
        return document.querySelector("[name=csrfmiddlewaretoken]").value;
    }
});