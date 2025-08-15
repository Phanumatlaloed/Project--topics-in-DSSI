document.addEventListener("DOMContentLoaded", function () {
    console.log("✅ Comment System Loaded!");

    // ตรวจสอบและเก็บข้อมูลผู้ใช้ปัจจุบันไว้ใช้
    let currentUserProfilePic = '/static/images/default-profile.png'; // ค่าเริ่มต้น
    let currentUsername = '';

    // พยายามดึงข้อมูลจาก DOM
    try {
        const profileImgElement = document.querySelector('.comment-form .comment-form-avatar img');
        if (profileImgElement) {
            currentUserProfilePic = profileImgElement.src;
        }
        
        const usernameElement = document.querySelector('.welcome-logout b');
        if (usernameElement) {
            currentUsername = usernameElement.textContent;
        }
        
        console.log("✅ ข้อมูลผู้ใช้: ", currentUsername, currentUserProfilePic);
    } catch (error) {
        console.error("❌ ไม่สามารถดึงข้อมูลผู้ใช้ได้:", error);
    }

    // ===== ADD COMMENT =====
    document.querySelectorAll(".comment-form").forEach(form => {
        form.addEventListener("submit", async function (e) {
            e.preventDefault();
            const postId = form.dataset.postId;
            const groupId = form.dataset.groupId; // ดึง Group ID
            const contentInput = form.querySelector("input[name='content']");
            const content = contentInput.value.trim();
            const csrfToken = document.querySelector("[name='csrfmiddlewaretoken']").value;

            if (!content) return;

            // ดึงข้อมูลโปรไฟล์จากฟอร์มปัจจุบัน (รูปภาพและชื่อผู้ใช้)
            try {
                const formProfileImg = form.querySelector('.comment-form-avatar img');
                if (formProfileImg) {
                    currentUserProfilePic = formProfileImg.src;
                }
            } catch (error) {
                console.warn("ไม่สามารถดึงรูปโปรไฟล์จากฟอร์มได้ ใช้ค่าที่เก็บไว้แทน");
            }

            // แก้ไข URL ตามบริบทให้ตรงกับ URL pattern ที่กำหนดใน path
            const url = groupId 
                ? `/group_post/${postId}/add_comment/` // ใช้ path ที่มีอยู่จริง
                : `/group_post/${postId}/add_comment/`;

            try {
                const response = await fetch(url, {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "X-CSRFToken": csrfToken
                    },
                    body: JSON.stringify({ content })
                });

                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }

                const data = await response.json();
                console.log("📊 ข้อมูลคอมเมนต์ที่ได้รับ:", data);

                if (data.success) {
                    const commentsList = document.getElementById(`comments-${postId}`);
                    const newComment = document.createElement("div");
                    newComment.className = "comment-item d-flex";
                    newComment.id = `comment-${data.comment_id}`;
                    newComment.setAttribute("data-comment-id", data.comment_id);

                    // สร้าง comment ในรูปแบบใหม่ - ใช้รูปภาพโปรไฟล์ที่มีอยู่แล้ว
                    newComment.innerHTML = `
                        <div class="comment-avatar">
                            <img src="${currentUserProfilePic}" alt="${currentUsername}" onerror="this.src='/static/images/default-profile.png'">
                        </div>
                        <div class="comment-content">
                            <div class="comment-bubble own-comment">
                                <div class="comment-author">${data.comment.user || currentUsername}</div>
                                <div class="comment-text">${data.comment.content}</div>
                            </div>
                            <div class="comment-meta">
                                <span class="comment-time">เมื่อสักครู่</span>
                                <div class="comment-actions">
                                    <button class="action-btn edit-comment" data-comment-id="${data.comment_id}">
                                        <i class="fas fa-edit"></i> แก้ไข
                                    </button>
                                    <button class="action-btn delete-comment" data-comment-id="${data.comment_id}">
                                        <i class="fas fa-trash"></i> ลบ
                                    </button>
                                </div>
                            </div>
                        </div>
                    `;
                    
                    // ลบข้อความ "ไม่มีความคิดเห็น" ถ้ามี
                    const noComments = commentsList.querySelector('.no-comments');
                    if (noComments) {
                        noComments.remove();
                    }
                    
                    commentsList.appendChild(newComment);
                    contentInput.value = "";
                    
                    // อัปเดตจำนวนคอมเมนต์
                    const commentCount = form.closest('.comments').querySelector('.comments-count');
                    if (commentCount) {
                        const count = parseInt(commentCount.textContent) + 1;
                        commentCount.textContent = count;
                    }

                    console.log("✅ คอมเมนต์ถูกเพิ่ม: ", data.comment_id);
                } else {
                    alert(data.message || "ไม่สามารถเพิ่มความคิดเห็นได้");
                }
            } catch (error) {
                console.error("❌ Error:", error);
                alert("เกิดข้อผิดพลาดในการเพิ่มความคิดเห็น");
            }
        });
    });

    // ===== DELETE COMMENT =====
    document.addEventListener("click", async function (event) {
        const btn = event.target.closest(".delete-comment");
        if (btn) {
            const commentId = btn.dataset.commentId;
            if (!commentId || commentId === "undefined") {
                console.error("❌ ไม่พบ Comment ID");
                alert("เกิดข้อผิดพลาด: ไม่พบ Comment ID");
                return;
            }

            if (confirm("คุณต้องการลบคอมเมนต์นี้ใช่ไหม?")) {
                const csrfToken = document.querySelector("[name='csrfmiddlewaretoken']").value;
                const commentElement = document.getElementById(`comment-${commentId}`);
                const commentForm = commentElement.closest('.comments').querySelector('.comment-form');
                const groupId = commentForm ? commentForm.dataset.groupId : '';
                
                // แก้ไข URL ตามบริบทให้ตรงกับ URL pattern ที่กำหนดใน path
                const url = groupId 
                    ? `/community/${groupId}/group_comment/${commentId}/delete/` // ใช้ path ที่กำหนดในรายการ path
                    : `/group_comment/${commentId}/delete/`;

                try {
                    const response = await fetch(url, {
                        method: "POST",
                        headers: {
                            "Content-Type": "application/json",
                            "X-CSRFToken": csrfToken
                        }
                    });

                    if (!response.ok) {
                        throw new Error(`HTTP error! status: ${response.status}`);
                    }

                    const data = await response.json();
                    if (data.success) {
                        if (commentElement) {
                            commentElement.style.opacity = "0";
                            commentElement.style.transition = "opacity 0.3s ease";
                            setTimeout(() => {
                                commentElement.remove();
                                
                                // อัปเดตจำนวนคอมเมนต์
                                const commentCount = commentForm.closest('.comments').querySelector('.comments-count');
                                if (commentCount) {
                                    const count = Math.max(0, parseInt(commentCount.textContent) - 1);
                                    commentCount.textContent = count;
                                    
                                    // เพิ่มข้อความ "ไม่มีความคิดเห็น" ถ้าเป็นคอมเมนต์สุดท้าย
                                    if (count === 0) {
                                        const commentsList = commentElement.closest('.comments-list');
                                        const noCommentsElement = document.createElement('div');
                                        noCommentsElement.className = 'no-comments';
                                        noCommentsElement.innerHTML = `
                                            <i class="fas fa-comment-slash"></i>
                                            <p>ยังไม่มีความคิดเห็น เป็นคนแรกที่แสดงความคิดเห็น!</p>
                                        `;
                                        commentsList.appendChild(noCommentsElement);
                                    }
                                }
                            }, 300);
                        }
                    } else {
                        alert(data.message || "ไม่สามารถลบความคิดเห็นได้");
                    }
                } catch (error) {
                    console.error("❌ Error:", error);
                    alert("เกิดข้อผิดพลาดในการลบความคิดเห็น");
                }
            }
        }
    });

    // ส่วนของการสร้างฟอร์มแก้ไขความคิดเห็น
    document.addEventListener("click", async function (event) {
        const btn = event.target.closest(".edit-comment");
        if (btn) {
            const commentId = btn.dataset.commentId;
            if (!commentId || commentId === "undefined") {
                console.error("❌ ไม่พบ Comment ID");
                alert("เกิดข้อผิดพลาด: ไม่พบ Comment ID");
                return;
            }

            const commentEl = document.getElementById(`comment-${commentId}`);
            const commentTextEl = commentEl.querySelector(".comment-text");
            const originalContent = commentTextEl.textContent;
            const commentBubble = commentEl.querySelector(".comment-bubble");
            const commentMeta = commentEl.querySelector(".comment-meta");
            
            // ซ่อนเนื้อหาความคิดเห็นเดิม
            commentBubble.style.display = "none";
            commentMeta.style.display = "none";
            
            // สร้างฟอร์มแก้ไขที่สวยงาม
            const commentContent = commentEl.querySelector(".comment-content");
            const editForm = document.createElement("div");
            editForm.className = "comment-edit-form";
            editForm.innerHTML = `
                <div class="edit-form-container">
                    <div class="edit-input-wrapper">
                        <input type="text" value="${originalContent}" class="edit-input" placeholder="แก้ไขความคิดเห็น...">
                    </div>
                    <div class="edit-actions">
                        <button type="button" class="save-edit-btn">
                            <i class="fas fa-check"></i> บันทึก
                        </button>
                        <button type="button" class="cancel-btn">
                            <i class="fas fa-times"></i> ยกเลิก
                        </button>
                    </div>
                </div>
            `;
            commentContent.appendChild(editForm);
            
            // เพิ่ม CSS inline เพื่อให้ฟอร์มสวยงาม
            const style = document.createElement('style');
            style.textContent = `
                .comment-edit-form {
                    margin-top: 8px;
                    margin-bottom: 8px;
                    width: 100%;
                }
                .edit-form-container {
                    background-color: #f8f9fa;
                    border-radius: 18px;
                    padding: 10px 15px;
                    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
                }
                .edit-input-wrapper {
                    margin-bottom: 8px;
                }
                .edit-input {
                    width: 100%;
                    border: 1px solid #ced4da;
                    border-radius: 20px;
                    padding: 8px 15px;
                    font-size: 14px;
                    transition: all 0.2s ease;
                }
                .edit-input:focus {
                    outline: none;
                    border-color: #ff9ed5;
                    box-shadow: 0 0 0 2px rgba(255, 105, 180, 0.2);
                }
                .edit-actions {
                    display: flex;
                    justify-content: flex-end;
                    gap: 8px;
                }
                .save-edit-btn, .cancel-btn {
                    border: none;
                    border-radius: 20px;
                    padding: 5px 12px;
                    font-size: 14px;
                    cursor: pointer;
                    transition: all 0.2s ease;
                    display: flex;
                    align-items: center;
                    gap: 5px;
                }
                .save-edit-btn {
                    background-color: #ff69b4;
                    color: white;
                }
                .save-edit-btn:hover {
                    background-color: #ff5ba7;
                }
                .cancel-btn {
                    background-color: #e9ecef;
                    color: #495057;
                }
                .cancel-btn:hover {
                    background-color: #dee2e6;
                }
            `;
            document.head.appendChild(style);
            
            // Auto focus input
            const editInput = editForm.querySelector(".edit-input");
            editInput.focus();
            editInput.setSelectionRange(editInput.value.length, editInput.value.length);
            
            // Cancel button handler
            const cancelBtn = editForm.querySelector(".cancel-btn");
            cancelBtn.addEventListener("click", function() {
                commentBubble.style.display = "block";
                commentMeta.style.display = "flex";
                editForm.remove();
            });
            
            // Save button handler
            const saveBtn = editForm.querySelector(".save-edit-btn");
            saveBtn.addEventListener("click", async function() {
                const newContent = editInput.value.trim();
                if (!newContent) return;
                
                const csrfToken = document.querySelector("[name='csrfmiddlewaretoken']").value;
                const commentForm = commentEl.closest('.comments').querySelector('.comment-form');
                const groupId = commentForm ? commentForm.dataset.groupId : '';
                
                // สร้าง URL ตามบริบท (กลุ่มหรือไม่)
                const url = groupId 
                    ? `/group_comment/${commentId}/edit/` // ใช้ path ที่มีอยู่จริง
                    : `/group_comment/${commentId}/edit/`;
                
                try {
                    saveBtn.disabled = true;
                    saveBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> กำลังบันทึก...';
                    
                    const response = await fetch(url, {
                        method: "POST",
                        headers: {
                            "Content-Type": "application/json",
                            "X-CSRFToken": csrfToken
                        },
                        body: JSON.stringify({ content: newContent })
                    });

                    if (!response.ok) {
                        throw new Error(`HTTP error! status: ${response.status}`);
                    }
                    
                    const data = await response.json();
                    if (data.success) {
                        commentTextEl.textContent = newContent;
                        commentBubble.style.display = "block";
                        commentMeta.style.display = "flex";
                        editForm.remove();
                        
                        // เพิ่มเอฟเฟกต์ highlight เมื่อแก้ไขสำเร็จ
                        commentBubble.style.backgroundColor = "#fffacd";
                        setTimeout(() => {
                            commentBubble.style.transition = "background-color 1s ease";
                            commentBubble.style.backgroundColor = "";
                        }, 100);
                    } else {
                        alert(data.message || "ไม่สามารถแก้ไขความคิดเห็นได้");
                    }
                } catch (error) {
                    console.error("❌ Error:", error);
                    alert("เกิดข้อผิดพลาดในการแก้ไขความคิดเห็น");
                } finally {
                    saveBtn.disabled = false;
                    saveBtn.innerHTML = '<i class="fas fa-check"></i> บันทึก';
                }
            });
        }
    });
});