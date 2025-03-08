document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll(".follow-form").forEach(form => {
        form.addEventListener("submit", function (event) {
            event.preventDefault();
            let button = this.querySelector(".follow-btn");
            let userId = button.dataset.userId;
            let formData = new FormData(this);

            if (!userId) {
                console.error("❌ userId is undefined or null");
                return;
            }

            fetch(this.action, {
                method: "POST",
                body: formData,
                headers: { "X-CSRFToken": formData.get("csrfmiddlewaretoken") }
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    if (data.is_following) {
                        button.classList.remove("btn-outline-primary");
                        button.classList.add("btn-danger");
                        button.textContent = "Unfollow";
                    } else {
                        button.classList.remove("btn-danger");
                        button.classList.add("btn-outline-primary");
                        button.textContent = "Follow";
                    }
                } else {
                    console.error("❌ Follow API error:", data.message);
                }
            })
            .catch(error => console.error("❌ Error fetching follow status:", error));
        });
    });

    // ✅ โหลดสถานะติดตามหลังจากรีเฟรชหน้าเว็บ
    document.querySelectorAll(".follow-btn").forEach(button => {
        let userId = button.dataset.userId;

        if (!userId) {
            console.error("❌ userId is undefined in follow status check.");
            return;
        }

        fetch(`/follow_status/${userId}/`)
            .then(response => response.json())
            .then(data => {
                if (data.is_following) {
                    button.classList.remove("btn-outline-primary");
                    button.classList.add("btn-danger");
                    button.textContent = "Unfollow";
                } else {
                    button.classList.remove("btn-danger");
                    button.classList.add("btn-outline-primary");
                    button.textContent = "Follow";
                }
            })
            .catch(error => console.error("❌ Error fetching follow status:", error));
    });
});
