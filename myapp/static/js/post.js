document.addEventListener("DOMContentLoaded", function () {
    const postForm = document.getElementById("postForm");

    if (postForm) {
        postForm.addEventListener("submit", function (event) {
            event.preventDefault();  // ✅ ป้องกันการโหลดหน้าใหม่
            
            let formData = new FormData(postForm);

            fetch(postForm.action, {
                method: "POST",
                body: formData,
                headers: { "X-Requested-With": "XMLHttpRequest" },
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // ✅ หา `<h3 class="mb-4">โพสต์</h3>` แล้วเพิ่มโพสต์ถัดจากมัน
                    const postSection = document.querySelector(".posts-section");
                    const postHeader = postSection.querySelector("h3");
                    const newPost = document.createElement("div");
                    newPost.classList.add("post", "card", "p-3", "mb-3", "shadow-sm");
                    newPost.id = `post-${data.post_id}`;
                    
                    newPost.innerHTML = `
                        <div class="post-header d-flex align-items-center">
                            <img src="/static/images/default-profile.png" class="profile-img me-2 rounded-circle" width="40" height="40">
                            <div class="d-flex flex-column">
                                <b>${data.username}</b>
                                <small class="text-muted">Just now</small>
                            </div>
                        </div>
                        <p class="mt-2">${data.content}</p>
                        
                        <div class="actions mt-2 d-flex gap-2">
                            <button class="btn btn-light like-btn" data-post-id="${data.post_id}">👍 Like</button>
                            <span>0 Likes</span>
                            <button class="btn btn-light share-btn">🔗 Share</button>
                            <button class="btn btn-light save-btn">💾 Save</button>
                            <button class="btn btn-danger delete-btn" data-post-id="${data.post_id}">🗑 Delete</button>
                        </div>
                    `;

                    postHeader.after(newPost); // ✅ เพิ่มโพสต์หลังหัวข้อ "โพสต์"
                    postForm.reset();  // ✅ ล้างฟอร์มหลังโพสต์สำเร็จ
                } else {
                    alert(data.message || "เกิดข้อผิดพลาดในการโพสต์");
                }
            })
            .catch(error => console.error("Error:", error));
        });
    }
});
