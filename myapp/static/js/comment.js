document.addEventListener("DOMContentLoaded", function () {
    // การเพิ่มคอมเมนต์
    document.querySelectorAll(".add-comment-form").forEach(form => {
        form.addEventListener("submit", function (event) {
            event.preventDefault();

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

                    form.querySelector("input[name='content']").value = ""; // เคลียร์ช่อง input

                    // ✅ ปิดเมนูดรอปดาวน์ทั้งหมด
                    document.querySelectorAll('.dropdown-menu').forEach(menu => {
                        menu.classList.remove('show');
                    });

                    // ✅ ปิดการแสดงเมนูบนเมนูดรอปดาวน์ของบูทสแตรป
                    const dropdownToggles = document.querySelectorAll('[data-bs-toggle="dropdown"]');
                    dropdownToggles.forEach(toggle => {
                        const dropdown = toggle.closest('.dropdown');
                        if (dropdown) {
                            const dropdownMenu = dropdown.querySelector('.dropdown-menu');
                            dropdownMenu.classList.remove('show');
                        }
                    });
                } else {
                    alert(`❌ Error: ${data.message}`);
                }
            })
            .catch(error => console.error("❌ Error:", error));
        });
    });

    // ✅ **Event Delegation สำหรับการลบคอมเมนต์**
    document.addEventListener("click", function (event) {
        if (event.target.classList.contains("delete-comment")) {
            let commentId = event.target.getAttribute("data-comment-id"); 
            let csrfToken = document.querySelector("input[name='csrfmiddlewaretoken']").value;

            console.log("Deleting comment ID:", commentId); // Debug

            if (!commentId || commentId === "undefined") {
                alert("❌ ไม่พบ comment ID!");
                return;
            }

            fetch(`/comment/delete/${commentId}/`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRFToken": csrfToken,
                    "X-Requested-With": "XMLHttpRequest"
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    let commentElement = document.getElementById(`comment-${commentId}`);
                    if (commentElement) {
                        commentElement.remove();
                    }
                } else {
                    alert(`❌ Error: ${data.message}`);
                }
            })
            .catch(error => console.error("❌ Error:", error));
        }
    });

    // ✅ **Event Delegation สำหรับการแก้ไขคอมเมนต์**
    document.addEventListener("click", function (event) {
        if (event.target.classList.contains("edit-comment")) {
            const commentId = event.target.getAttribute("data-comment-id");
            const commentDiv = document.getElementById(`comment-${commentId}`);
            const contentSpan = commentDiv.querySelector(".comment-content");
            const originalContent = contentSpan.textContent;

            // ✅ ป้องกันการเปิดช่องแก้ไขซ้ำ
            if (commentDiv.querySelector(".edit-container")) return;

            // ✅ สร้าง div container สำหรับ input และปุ่มบันทึก
            const editContainer = document.createElement("div");
            editContainer.className = "edit-container d-flex gap-2";

            // ✅ สร้างช่องกรอกข้อความ
            const input = document.createElement("input");
            input.type = "text";
            input.value = originalContent;
            input.className = "form-control";

            // ✅ สร้างปุ่มบันทึก
            const saveButton = document.createElement("button");
            saveButton.textContent = "💾 บันทึก";
            saveButton.className = "btn btn-primary btn-sm";

            // ✅ เพิ่ม input และปุ่มบันทึกลงใน container
            editContainer.appendChild(input);
            editContainer.appendChild(saveButton);

            // ✅ แทนที่เนื้อหาเดิมด้วย container
            contentSpan.style.display = "none";
            contentSpan.parentNode.insertBefore(editContainer, contentSpan);

            // ✅ โฟกัสที่ช่องกรอกข้อความ
            input.focus();

            // ✅ จัดการการบันทึกเมื่อกดปุ่มเซฟ
            saveButton.addEventListener("click", function () {
                saveComment();
            });

            // ✅ ฟังก์ชันสำหรับบันทึกคอมเมนต์
            function saveComment() {
                const newContent = input.value.trim();
                if (newContent && newContent !== originalContent) {
                    const csrfToken = document.querySelector("[name=csrfmiddlewaretoken]").value;

                    fetch(`/comment/edit/${commentId}/`, {
                        method: "POST",
                        headers: {
                            "Content-Type": "application/x-www-form-urlencoded",
                            "X-CSRFToken": csrfToken,
                            "X-Requested-With": "XMLHttpRequest"
                        },
                        body: `content=${encodeURIComponent(newContent)}`
                    })
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            contentSpan.textContent = data.content;
                        } else {
                            alert("เกิดข้อผิดพลาดในการอัปเดตคอมเมนต์");
                        }
                    })
                    .catch(error => console.error("เกิดข้อผิดพลาด:", error))
                    .finally(() => {
                        contentSpan.style.display = "";
                        editContainer.remove();
                    });
                } else {
                    contentSpan.style.display = "";
                    editContainer.remove();
                }
            }
        }
    });

    function updateDropdown() {
        document.querySelectorAll('.dropdown-menu').forEach(menu => {
            menu.classList.remove('show');
        });
    }
    
    // เรียกใช้หลังจากมีการเพิ่มหรือแก้ไขความคิดเห็น
    updateDropdown();
    

});
