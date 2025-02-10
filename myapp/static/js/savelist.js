document.addEventListener("DOMContentLoaded", function () {
    // ✅ เพิ่ม event listener ให้ปุ่ม Save ทุกปุ่ม
    document.querySelectorAll(".save-btn").forEach(button => {
        button.addEventListener("click", function () {
            let postId = this.dataset.postId;  // ดึง ID ของโพสต์
            let btn = this;

            fetch(`/save/${postId}/`, {  // ✅ URL ต้องตรงกับ `urls.py`
                method: "POST",
                headers: {
                    "X-CSRFToken": getCSRFToken(),
                    "X-Requested-With": "XMLHttpRequest"
                }
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

    // ✅ เพิ่ม event listener ให้ปุ่ม Remove บนหน้า Saved List
    document.querySelectorAll(".remove-btn").forEach(button => {
        button.addEventListener("click", function () {
            let postId = this.dataset.postId;
            let card = this.closest(".col-md-6, .col-lg-4");

            fetch(`/save/${postId}/`, {  // ✅ URL ต้องตรงกับ `urls.py`
                method: "POST",
                headers: {
                    "X-CSRFToken": getCSRFToken(),
                    "X-Requested-With": "XMLHttpRequest"
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.success && !data.saved) {
                    card.remove();  // ✅ ลบโพสต์ออกจาก Saved List
                } else {
                    alert("❌ ไม่สามารถลบโพสต์นี้ได้");
                }
            })
            .catch(error => console.error("❌ Error:", error));
        });
    });

    // ✅ ฟังก์ชันดึง CSRF Token
    function getCSRFToken() {
        let csrfToken = document.querySelector("input[name='csrfmiddlewaretoken']");
        return csrfToken ? csrfToken.value : "";
    }
});
