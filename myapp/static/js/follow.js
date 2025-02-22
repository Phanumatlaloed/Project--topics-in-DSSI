document.addEventListener("DOMContentLoaded", function () {
    const followButton = document.getElementById("follow-button");

    if (followButton) {
        followButton.addEventListener("click", function () {
            const userId = this.dataset.userId;
            const followersCountSpan = document.getElementById("followers-count");
            const csrfToken = document.querySelector("input[name='csrfmiddlewaretoken']").value;

            // ✅ แสดงสถานะกำลังดำเนินการ
            followButton.textContent = "Processing...";
            followButton.disabled = true;

            fetch(`/follow/${userId}/`, {
                method: "POST",
                headers: {
                    "X-CSRFToken": csrfToken,
                    "Content-Type": "application/json"
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // ✅ อัปเดตปุ่ม Follow/Unfollow
                    if (data.is_following) {
                        followButton.textContent = "Unfollow";
                        followButton.classList.remove("btn-outline-primary");
                        followButton.classList.add("btn-danger");
                    } else {
                        followButton.textContent = "Follow";
                        followButton.classList.remove("btn-danger");
                        followButton.classList.add("btn-outline-primary");
                    }

                    // ✅ อัปเดตจำนวน Followers
                    followersCountSpan.textContent = data.followers_count;
                } else {
                    alert(data.message);
                }
            })
            .catch(error => {
                console.error("Error:", error);
                alert("เกิดข้อผิดพลาด กรุณาลองใหม่อีกครั้ง!");
            })
            .finally(() => {
                // ✅ เปิดปุ่มให้กดใหม่
                followButton.disabled = false;
            });
        });
    }
});