document.addEventListener("DOMContentLoaded", function () {
    // ✅ ปุ่ม Save / Unsave
    document.querySelectorAll(".save-btn").forEach(button => {
        button.addEventListener("click", function () {
            let postId = this.dataset.postId;
            let groupId = this.dataset.groupId;  // รับค่า group_id จากปุ่มหรือ HTML element
            let btn = this;

            fetch(`/community/${groupId}/group/post/${postId}/save/`, { 
                method: "POST",
                headers: {
                    "X-CSRFToken": getCSRFToken(),
                    "X-Requested-With": "XMLHttpRequest",
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({})
            })
            
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    if (data.saved) {
                        btn.innerHTML = "💾 Unsave";
                        btn.classList.add("btn-success");
                        btn.classList.remove("btn-light");
                    } else {
                        btn.innerHTML = "💾 Save";
                        btn.classList.add("btn-light");
                        btn.classList.remove("btn-success");
                    }
                } else {
                    alert("❌ ไม่สามารถบันทึกโพสต์ได้");
                }
            })
            .catch(error => console.error("❌ Error:", error));
        });
    });

    function getCSRFToken() {
        let csrfToken = document.querySelector("input[name='csrfmiddlewaretoken']");
        return csrfToken ? csrfToken.value : "";
    }
});
