document.addEventListener("DOMContentLoaded", function () {
    const postForm = document.getElementById("postForm");
    postForm.addEventListener("submit", function (e) {
        e.preventDefault();

        const formData = new FormData(postForm);
        fetch("/create_post/", {
            method: "POST",
            body: formData,
            headers: { "X-CSRFToken": document.querySelector("[name=csrfmiddlewaretoken]").value },
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                window.location.reload();
            } else {
                alert("โพสต์ไม่สำเร็จ: " + data.message);
            }
        })
        .catch(error => console.error("Error:", error));
    });
});