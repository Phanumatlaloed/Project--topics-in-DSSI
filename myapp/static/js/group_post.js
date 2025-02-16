document.addEventListener("DOMContentLoaded", function () {
    // ✅ ดึง CSRF Token จากคุกกี้
    function getCSRFToken() {
        let cookieValue = null;
        if (document.cookie && document.cookie !== '') {
            const cookies = document.cookie.split(';');
            for (let i = 0; i < cookies.length; i++) {
                const cookie = cookies[i].trim();
                if (cookie.startsWith('csrftoken=')) {
                    cookieValue = cookie.substring(10);
                    break;
                }
            }
        }
        return cookieValue;
    }
    
    // ✅ Share Post
    document.querySelectorAll(".share-btn").forEach(button => {
        button.addEventListener("click", function () {
            let postId = this.getAttribute("data-post-id");
            fetch(`/group/post/${postId}/share/`, {
                method: "POST",
                headers: {
                    "X-CSRFToken": getCSRFToken(),
                    "Content-Type": "application/json"
                }
            })
            .then(response => response.json())
            .then(data => alert(data.message));
        });
    });

    // ✅ Delete Post
    document.querySelectorAll(".delete-btn").forEach(button => {
        button.addEventListener("click", function () {
            let postId = this.getAttribute("data-post-id");
            if (confirm("Are you sure?")) {
                fetch(`/group/post/delete/${postId}/`, {
                    method: "POST",
                    headers: {
                        "X-CSRFToken": getCSRFToken(),
                        "Content-Type": "application/json"
                    }
                })
                .then(response => response.json())
                .then(data => {
                    alert(data.message);
                    document.getElementById(`post-${postId}`).remove();
                });
            }
        });
    });
});
