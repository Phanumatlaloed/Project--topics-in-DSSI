document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll(".follow-form").forEach(form => {
        form.addEventListener("submit", function (event) {
            event.preventDefault();
            let button = this.querySelector(".follow-btn");
            let userId = button.dataset.userId;
            let csrfToken = document.querySelector("[name=csrfmiddlewaretoken]").value;

            if (!userId) {
                console.error("❌ userId is undefined or null");
                return;
            }

            fetch(`/follow/${userId}/`, {
                method: "POST",
                headers: {
                    "X-CSRFToken": csrfToken,
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({})
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    if (data.is_following) {
                        button.classList.remove("btn-outline-primary");
                        button.classList.add("btn-danger");
                        button.textContent = "ติดตามแล้ว";
                    } else {
                        button.classList.remove("btn-danger");
                        button.classList.add("btn-outline-primary");
                        button.textContent = "ติดตาม";
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
                    button.textContent = "ติดตามแล้ว";
                } else {
                    button.classList.remove("btn-danger");
                    button.classList.add("btn-outline-primary");
                    button.textContent = "ติดตาม";
                }
            })
            .catch(error => console.error("❌ Error fetching follow status:", error));
    });
});
