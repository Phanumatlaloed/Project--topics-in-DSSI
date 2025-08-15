document.addEventListener("DOMContentLoaded", function() {
    console.log("✅ Enhanced Comments System Loaded!");
    
    // ===== ENABLE/DISABLE SUBMIT BUTTON =====
    document.querySelectorAll('.comment-input').forEach(input => {
        const submitButton = input.parentElement.querySelector('.comment-submit');
        
        // Initial button state
        submitButton.disabled = input.value.trim() === '';
        
        // Update button state on input
        input.addEventListener('input', function() {
            submitButton.disabled = this.value.trim() === '';
        });
    });
    
    // ===== ADD COMMENT =====
    document.querySelectorAll(".comment-form").forEach(form => {
        form.addEventListener("submit", async function(event) {
            event.preventDefault();
            
            const postId = this.dataset.postId;
            const contentInput = this.querySelector("input[name='content']");
            const content = contentInput.value.trim();
            const csrfToken = document.querySelector("input[name='csrfmiddlewaretoken']").value;
            const submitButton = this.querySelector('.comment-submit');
            
            if (!content) return;
            
            // Disable input and button during submission
            contentInput.disabled = true;
            submitButton.disabled = true;
            
            try {
                let response = await fetch(`/add_comment/${postId}/`, {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/x-www-form-urlencoded",
                        "X-CSRFToken": csrfToken
                    },
                    body: new URLSearchParams({ "content": content })
                });
                
                let data = await response.json();
                console.log("API Response:", data); // เพิ่มการแสดง log เพื่อตรวจสอบข้อมูลที่ได้รับ
                
                if (data.success) {
                    // Get comment container
                    let commentsList = document.getElementById(`comments-${postId}`);
                    
                    // Remove "no comments" message if exists
                    const noComments = commentsList.querySelector('.no-comments');
                    if (noComments) {
                        noComments.remove();
                    }
                    
                    // Determine avatar URL - แก้ไขเส้นทาง URL ให้ถูกต้อง ตามที่เก็บรูปไว้ที่ media/profile_picture
                    const avatarUrl = data.user_avatar || '/media/profile_pictures/';
                    
                    // Create new comment element
                    const newComment = document.createElement('div');
                    newComment.classList.add('comment-item', 'd-flex');
                    newComment.id = `comment-${data.comment_id}`;
                    newComment.innerHTML = `
                        <div class="comment-avatar">
                            <img src="${avatarUrl}" alt="${data.username}" onerror="this.src='/static/images/default-profile.png'">
                        </div>
                        <div class="comment-content">
                            <div class="comment-bubble own-comment">
                                <div class="comment-author">${data.username}</div>
                                <div class="comment-text">${data.content}</div>
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
                    
                    // Add to the top of the list
                    commentsList.appendChild(newComment);
                    
                    // Update comment count
                    updateCommentCount(postId, 1);
                    
                    // Show success notification
                    showNotification('เพิ่มความคิดเห็นสำเร็จ');
                    
                    // Clear input
                    contentInput.value = '';
                } else {
                    showNotification(`เกิดข้อผิดพลาด: ${data.message}`, true);
                }
            } catch (error) {
                console.error("❌ Error:", error);
                showNotification('เกิดข้อผิดพลาดในการเพิ่มความคิดเห็น', true);
            } finally {
                // Re-enable input and button
                contentInput.disabled = false;
                submitButton.disabled = true;
                contentInput.focus();
            }
        });
    });
    
    // ===== EDIT COMMENT =====
    document.addEventListener("click", function(event) {
        // ปรับปรุงการตรวจจับการคลิกปุ่มแก้ไข
        const editButton = event.target.closest('.edit-comment');
        
        if (editButton) {
            const commentId = editButton.dataset.commentId;
            const commentItem = document.getElementById(`comment-${commentId}`);
            
            if (!commentItem) return;
            
            const commentText = commentItem.querySelector('.comment-text');
            if (!commentText) return; // เพิ่มการตรวจสอบว่าพบองค์ประกอบหรือไม่
            
            const originalContent = commentText.textContent.trim();
            
            // Check if already in edit mode
            if (commentItem.classList.contains('edit-mode')) return;
            
            // Add edit mode class
            commentItem.classList.add('edit-mode');
            
            // Create edit form
            const editForm = document.createElement('div');
            editForm.className = 'comment-edit-form';
            editForm.innerHTML = `
                <input type="text" value="${originalContent}" class="edit-input">
                <button type="button" class="save-btn">บันทึก</button>
                <button type="button" class="cancel-btn">ยกเลิก</button>
            `;
            
            // ตรวจสอบว่า commentText ยังอยู่ในเอกสารหรือไม่
            if (commentText.isConnected) {
                // Insert after comment text
                commentText.insertAdjacentElement('afterend', editForm);
                
                // ซ่อนข้อความต้นฉบับ
                commentText.style.display = 'none';
                
                // Focus input and position cursor at end
                const input = editForm.querySelector('input');
                input.focus();
                input.selectionStart = input.value.length;
                
                // Cancel edit
                editForm.querySelector('.cancel-btn').addEventListener('click', function() {
                    editForm.remove();
                    commentItem.classList.remove('edit-mode');
                    commentText.style.display = '';
                });
                
                // Save edit
                editForm.querySelector('.save-btn').addEventListener('click', async function() {
                    const newContent = input.value.trim();
                    
                    if (!newContent || newContent === originalContent) {
                        editForm.remove();
                        commentItem.classList.remove('edit-mode');
                        commentText.style.display = '';
                        return;
                    }
                    
                    try {
                        const csrfToken = document.querySelector("input[name='csrfmiddlewaretoken']").value;
                        
                        let response = await fetch(`/comment/edit/${commentId}/`, {
                            method: "POST",
                            headers: {
                                "Content-Type": "application/x-www-form-urlencoded",
                                "X-CSRFToken": csrfToken
                            },
                            body: `content=${encodeURIComponent(newContent)}`
                        });
                        
                        let data = await response.json();
                        console.log("Edit Response:", data); // เพิ่มการแสดง log
                        
                        if (data.success) {
                            commentText.textContent = data.content;
                            commentText.style.display = ''; // แสดงข้อความหลังจากแก้ไข
                            showNotification('แก้ไขความคิดเห็นสำเร็จ');
                        } else {
                            showNotification('เกิดข้อผิดพลาดในการแก้ไขความคิดเห็น', true);
                        }
                    } catch (error) {
                        console.error("❌ Error:", error);
                        showNotification('เกิดข้อผิดพลาดในการแก้ไขความคิดเห็น', true);
                    } finally {
                        editForm.remove();
                        commentItem.classList.remove('edit-mode');
                        commentText.style.display = '';
                    }
                });
            }
        }
    });
    
    // ===== DELETE COMMENT =====
    document.addEventListener("click", function(event) {
        // ปรับปรุงการตรวจจับการคลิกปุ่มลบ
        const deleteButton = event.target.closest('.delete-comment');
        
        if (deleteButton) {
            const commentId = deleteButton.dataset.commentId;
            
            if (confirm("คุณต้องการลบความคิดเห็นนี้ใช่หรือไม่?")) {
                deleteComment(commentId);
            }
        }
    });
    
    async function deleteComment(commentId) {
        try {
            const csrfToken = document.querySelector("input[name='csrfmiddlewaretoken']").value;
            
            let response = await fetch(`/comment/delete/${commentId}/`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRFToken": csrfToken
                }
            });
            
            let data = await response.json();
            console.log("Delete Response:", data); // เพิ่มการแสดง log
            
            if (data.success) {
                const commentElement = document.getElementById(`comment-${commentId}`);
                
                if (commentElement) {
                    // Get post ID
                    const commentsList = commentElement.closest('.comments-list');
                    const postId = commentsList.id.replace('comments-', '');
                    
                    // Fade out and remove
                    commentElement.style.opacity = '0';
                    commentElement.style.transform = 'translateY(-10px)';
                    commentElement.style.transition = 'all 0.3s ease';
                    
                    setTimeout(() => {
                        commentElement.remove();
                        
                        // Update comment count
                        updateCommentCount(postId, -1);
                        
                        // If no more comments, add the no comments message
                        if (commentsList.children.length === 0) {
                            commentsList.innerHTML = `
                                <div class="no-comments">
                                    <i class="fas fa-comment-slash"></i>
                                    <p>ยังไม่มีความคิดเห็น เป็นคนแรกที่แสดงความคิดเห็น!</p>
                                </div>
                            `;
                        }
                    }, 300);
                    
                    showNotification('ลบความคิดเห็นสำเร็จ');
                }
            } else {
                showNotification('เกิดข้อผิดพลาดในการลบความคิดเห็น', true);
            }
        } catch (error) {
            console.error("❌ Error:", error);
            showNotification('เกิดข้อผิดพลาดในการลบความคิดเห็น', true);
        }
    }
    
    // ===== UTILITY FUNCTIONS =====
    
    // Update comment count
    function updateCommentCount(postId, change) {
        const commentsSection = document.querySelector(`.comments-count`);
        
        if (commentsSection) {
            const currentCount = parseInt(commentsSection.textContent || '0');
            const newCount = Math.max(0, currentCount + change);
            commentsSection.textContent = newCount;
        }
    }
    
    // Show notification
    function showNotification(message, isError = false) {
        // Check if notification element exists, create if not
        let notification = document.getElementById('comment-notification');
        
        if (!notification) {
            notification = document.createElement('div');
            notification.id = 'comment-notification';
            notification.className = 'comment-notification';
            notification.innerHTML = `
                <i class="fas fa-check-circle"></i>
                <span id="notification-message"></span>
                <button class="comment-notification-close">
                    <i class="fas fa-times"></i>
                </button>
            `;
            document.body.appendChild(notification);
            
            // Add event listener to close button
            notification.querySelector('.comment-notification-close').addEventListener('click', function() {
                notification.classList.remove('show');
            });
        }
        
        const messageElement = notification.querySelector('#notification-message');
        
        if (messageElement) {
            messageElement.textContent = message;
            
            if (isError) {
                notification.style.backgroundColor = '#ff5252';
                notification.querySelector('i').className = 'fas fa-exclamation-circle';
            } else {
                notification.style.backgroundColor = '#ff6b9d';
                notification.querySelector('i').className = 'fas fa-check-circle';
            }
            
            notification.classList.add('show');
            
            // Auto hide after 3 seconds
            setTimeout(() => {
                notification.classList.remove('show');
            }, 3000);
        }
    }
});