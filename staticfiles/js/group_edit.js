document.addEventListener("DOMContentLoaded", function () {
    console.log("✅ group_edit.js Loaded!");

    function getCSRFToken() {
        // Try to get from element
        let csrfInput = document.querySelector("[name=csrfmiddlewaretoken]");
        if (csrfInput) return csrfInput.value;
        
        // Fallback to cookie
        let cookieValue = null;
        if (document.cookie && document.cookie !== '') {
            let cookies = document.cookie.split(';');
            for (let i = 0; i < cookies.length; i++) {
                let cookie = cookies[i].trim();
                if (cookie.startsWith("csrftoken=")) {
                    cookieValue = cookie.substring("csrftoken=".length, cookie.length);
                    break;
                }
            }
        }
        return cookieValue;
    }

    // Handler for removing existing media files
    document.querySelectorAll(".remove-existing-file").forEach((button) => {
        button.addEventListener("click", function () {
            const mediaId = this.getAttribute("data-file-id");
            const groupId = this.closest("form").getAttribute("data-group-id") || '';
            console.log(`📌 Trying to delete media ID: ${mediaId}, Group ID: ${groupId}`);

            // URL is same for both group and regular posts
            fetch(`/delete_media/${mediaId}/`, {
                method: "DELETE",
                headers: {
                    "X-CSRFToken": getCSRFToken(),
                    "X-Requested-With": "XMLHttpRequest",
                },
            })
            .then((response) => response.json())
            .then((data) => {
                if (data.success) {
                    console.log("✅ Media deleted successfully:", mediaId);
                    this.parentElement.remove();
                } else {
                    console.error("❌ Error deleting media:", data.error);
                    alert("ไม่สามารถลบไฟล์สื่อได้: " + (data.error || "เกิดข้อผิดพลาด"));
                }
            })
            .catch((error) => {
                console.error("❌ AJAX Error:", error);
                alert("เกิดข้อผิดพลาดในการลบไฟล์สื่อ");
            });
        });
    });
    
    // Preview uploaded images/videos in edit mode
    const imageInput = document.getElementById("id_images");
    const videoInput = document.getElementById("id_videos");
    const previewContainer = document.getElementById("media-preview");
    
    if (imageInput && previewContainer) {
        imageInput.addEventListener("change", function() {
            previewFiles(this.files, 'image');
        });
    }
    
    if (videoInput && previewContainer) {
        videoInput.addEventListener("change", function() {
            previewFiles(this.files, 'video');
        });
    }
    
    function previewFiles(files, type) {
        if (!previewContainer || files.length === 0) return;
        
        for (const file of files) {
            const previewItem = document.createElement('div');
            previewItem.className = 'preview-item';
            
            if (type === 'image') {
                const img = document.createElement('img');
                img.src = URL.createObjectURL(file);
                previewItem.appendChild(img);
            } else if (type === 'video') {
                const videoThumb = document.createElement('div');
                videoThumb.className = 'video-thumbnail';
                
                const video = document.createElement('video');
                video.src = URL.createObjectURL(file);
                videoThumb.appendChild(video);
                
                const playOverlay = document.createElement('div');
                playOverlay.className = 'play-overlay';
                playOverlay.innerHTML = '<i class="fas fa-play-circle"></i>';
                videoThumb.appendChild(playOverlay);
                
                previewItem.appendChild(videoThumb);
            }
            
            const removeBtn = document.createElement('button');
            removeBtn.className = 'remove-btn';
            removeBtn.innerHTML = '<i class="fas fa-times"></i>';
            removeBtn.type = 'button';
            removeBtn.onclick = function() {
                previewItem.remove();
            };
            
            previewItem.appendChild(removeBtn);
            previewContainer.appendChild(previewItem);
        }
    }
});