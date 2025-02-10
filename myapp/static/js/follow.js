document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll(".follow-form").forEach(form => {
        form.addEventListener("submit", function (e) {
            e.preventDefault();
            let button = this.querySelector(".follow-btn");
            let userId = button.dataset.userId;
            
            fetch(`/follow/${userId}/`, {
                method: "POST",
                headers: { "X-CSRFToken": this.querySelector("input[name='csrfmiddlewaretoken']").value },
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    if (button.textContent.trim() === "Follow") {
                        button.textContent = "Unfollow";
                        button.classList.remove("btn-outline-primary");
                        button.classList.add("btn-danger");
                    } else {
                        button.textContent = "Follow";
                        button.classList.remove("btn-danger");
                        button.classList.add("btn-outline-primary");
                    }
                } else {
                    alert(data.message);
                }
            })
            .catch(error => console.error("Follow error:", error));
        });
    });
});
